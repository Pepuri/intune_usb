"""Local candidate snapshots and a gated writer for ONE empty-target sample policy."""
import base64
import json
import uuid
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote

import httpx
from dotenv import dotenv_values

from app.store import ROOT
from app.runtime import write_flag
from .pair_policy import compile_policy, digest, validate_manifest, POLICY_ID, POLICY_NAME, PairPolicyError, kst_day
from .sample_directory import SampleDirectory, LAB_LOCK, PCS, GRAPH, LabError, utc_stamp

CONFIG_PATH = '/deviceManagement/deviceConfigurations/' + POLICY_ID
LEGACY_URIS = {
    './Vendor/MSFT/Defender/Configuration/DeviceControl/PolicyGroups/%7b76c0bb29-79b2-5216-9874-2a30d7379e23%7d/GroupData',
    './Vendor/MSFT/Defender/Configuration/DeviceControl/PolicyRules/%7b6bbcf9c3-5a75-5dfc-9216-489b615d7a1e%7d/RuleData',
}


class PairPolicyService:
    def __init__(self, store, tenant_id, directory=None, transport=None, enabled=None, today=None):
        self.store = store
        self.directory = directory or SampleDirectory(store, tenant_id)
        self.transport = transport
        self._enabled = enabled
        self.today = today or kst_day

    @property
    def enabled(self):
        if self._enabled is not None:
            return self._enabled
        return write_flag('USB_PAIR_POLICY_WRITES', '.env.pair-policy')

    def prepare(self, source='manual-api'):
        with LAB_LOCK, self.store.connect() as db:
            rows = self.store.rows(db, 'approvals')
            fingerprint = digest({'day': self.today().isoformat(), 'rows': rows, 'roster': self.directory.config['users']})
            cached = self.store.get(db, 'pair_policy', 'candidate')
            if cached and cached['input_fingerprint'] == fingerprint:
                return cached['manifest']
            manifest = compile_policy(rows, self.directory.config['users'], self.today())
            self.store.save(db, 'pair_policy', 'candidate', {'input_fingerprint': fingerprint, 'manifest': manifest,
                            'source': source, 'generated_at': utc_stamp()})
            self.store.save(db, 'pair_policy_versions', manifest['version'], manifest)
            return manifest

    def preview(self):
        manifest = self.prepare()
        with self.store.connect() as db:
            runtime = self.store.get(db, 'pair_policy', 'published')
            events = sorted(self.store.rows(db, 'pair_policy_events'), key=lambda r:r['at'], reverse=True)[:15]
        return dict(manifest, writes_enabled=self.enabled, published=runtime, events=events,
                    changes_pending=not runtime or runtime.get('version') != manifest['version'])

    def request(self, method, path, body=None, etag=None, *, beta=False, reference=None):
        plain_path = CONFIG_PATH+'/getOmaSettingPlainTextValue'
        if not (method == 'GET' and path in (CONFIG_PATH, CONFIG_PATH+'/assignments',plain_path) or
                self.enabled and method == 'PATCH' and path == CONFIG_PATH):
            raise PairPolicyError('지정 샘플 정책의 조회·갱신만 허용됩니다.')
        if beta and (method != 'GET' or path != CONFIG_PATH):
            raise PairPolicyError('Beta API는 지정 정책 암호화 메타데이터 조회만 허용합니다.')
        if path == plain_path:
            if not isinstance(reference,str) or not reference or len(reference)>2000:
                raise PairPolicyError('암호화 XML 참조가 유효하지 않습니다.')
            path += "(secretReferenceValueId='"+quote(reference,safe='')+"')"
        if method == 'PATCH' and (set(body) != {'@odata.type','description','omaSettings'} or
                                  body['@odata.type'] != '#microsoft.graph.windows10CustomConfiguration'):
            raise PairPolicyError('정책 XML 설정 외 변경은 허용하지 않습니다.')
        headers = {'Authorization': 'Bearer '+self.directory.tokens.token('https://graph.microsoft.com')}
        if etag:
            headers['If-Match'] = etag
        try:
            with httpx.Client(timeout=20, transport=self.transport, follow_redirects=False) as client:
                origin='https://graph.microsoft.com/beta' if beta else GRAPH
                response = client.request(method, origin+path, json=body, headers=headers)
            if not response.is_success:
                raise PairPolicyError('Intune Graph HTTP '+str(response.status_code)+' · 정책 구성 권한 또는 연결을 확인해 주세요.')
            return response.json() if response.content else {}
        except httpx.RequestError:
            raise PairPolicyError('Intune 정책 연결에 실패했습니다.') from None

    @staticmethod
    def canonical(settings):
        try:
            return sorted((s['omaUri'].casefold(), ET.canonicalize(
                base64.b64decode(s['value'],validate=True).decode('utf-8-sig'),strip_text=True)) for s in settings)
        except (KeyError,ValueError,UnicodeError,ET.ParseError):
            raise PairPolicyError('XML 설정 값을 정규화하지 못했습니다.') from None

    def read_policy(self):
        policy=self.request('GET',CONFIG_PATH)
        if any(s.get('value')=='PGEvPg==' for s in policy.get('omaSettings',[])):
            # v1.0 omits encryption metadata. Beta is read-only here; the documented
            # v1.0 plaintext function retrieves the actual value for each reference.
            metadata=self.request('GET',CONFIG_PATH,beta=True)
            if (metadata.get('id')!=POLICY_ID or
                {s['omaUri'] for s in metadata.get('omaSettings',[])}!={s['omaUri'] for s in policy.get('omaSettings',[])}):
                raise PairPolicyError('암호화 XML 조회 중 정책 구성이 바뀌었습니다.')
            def resolve(item):
                item=dict(item)
                if item.get('isEncrypted'):
                    value=self.request('GET',CONFIG_PATH+'/getOmaSettingPlainTextValue',
                                       reference=item.get('secretReferenceValueId')).get('value')
                    if not isinstance(value,str):
                        raise PairPolicyError('암호화 XML 원문을 조회하지 못했습니다.')
                    try:
                        ET.fromstring(value)
                    except ET.ParseError:
                        raise PairPolicyError('암호화 XML 원문이 유효하지 않습니다.') from None
                    item['value']=base64.b64encode(value.encode('utf-8')).decode()
                if item.get('value')=='PGEvPg==':
                    raise PairPolicyError('XML 자리표시자를 원문으로 확인할 수 없습니다.')
                item.pop('secretReferenceValueId',None)
                item.pop('isEncrypted',None)
                return item
            with ThreadPoolExecutor(max_workers=6) as pool:
                policy['omaSettings']=list(pool.map(resolve,metadata.get('omaSettings',[])))
        return policy

    def publish(self, version, who, source='manual-api'):
        if not self.enabled:
            raise PairPolicyError('실제 정책 쓰기는 비활성입니다. 정책 구성 쓰기 권한 승인 후 활성화가 필요합니다.')
        with LAB_LOCK:
            manifest = self.prepare(source)
            if version != manifest['version']:
                raise PairPolicyError('원장이 변경되었습니다. 최신 페어링 미리보기를 확인해 주세요.')
            validate_manifest(manifest)
            try:
                self.directory.preflight()
                assignments = self.request('GET', CONFIG_PATH+'/assignments')
                targets = assignments.get('value', [])
                if assignments.get('@odata.nextLink') or len(targets) != 1:
                    raise PairPolicyError('샘플 정책은 빈 PC 그룹 하나에만 할당되어야 합니다.')
                target = targets[0].get('target', {})
                if (target.get('@odata.type') != '#microsoft.graph.groupAssignmentTarget' or target.get('groupId') != PCS
                        or target.get('deviceAndAppManagementAssignmentFilterType', 'none') != 'none'
                        or target.get('deviceAndAppManagementAssignmentFilterId')):
                    raise PairPolicyError('빈 PC 그룹 외 정책 할당 또는 필터가 있어 중단했습니다.')
                included = {p['user_object_id'] for p in manifest['pairs']}
                for index, mapped in enumerate(self.directory.config['users'], 1):
                    if mapped['object_id'] not in included:
                        continue
                    user = self.directory.request('GET', '/users/'+mapped['object_id'])
                    if (user.get('id') != mapped['object_id'] or user.get('userPrincipalName') != mapped['upn']
                            or user.get('accountEnabled') is not False or user.get('assignedLicenses') != []
                            or user.get('employeeId') != f'USBS261028-{index:03d}'):
                        raise PairPolicyError('비활성·무라이선스 샘플 사용자 조건을 확인하지 못했습니다.')
                current = self.read_policy()
                if (current.get('id') != POLICY_ID or current.get('displayName') != POLICY_NAME
                        or current.get('@odata.type') != '#microsoft.graph.windows10CustomConfiguration'):
                    raise PairPolicyError('지정된 샘플 Custom 정책이 아닙니다.')
                allowed_uris = LEGACY_URIS | {s['omaUri'] for s in manifest['policy_body']['omaSettings']}
                with self.store.connect() as db:
                    previous = self.store.get(db, 'pair_policy', 'published')
                    if previous:
                        old = self.store.get(db, 'pair_policy_versions', previous['version'])
                        allowed_uris |= {s['omaUri'] for s in old['policy_body']['omaSettings']}
                if any(s['omaUri'] not in allowed_uris for s in current.get('omaSettings', [])):
                    raise PairPolicyError('정책에 알 수 없는 기존 설정이 있어 덮어쓰기를 중단했습니다.')
            except LabError as error:
                raise PairPolicyError(str(error)) from None
            event = {'id': uuid.uuid4().hex, 'at': utc_stamp(), 'version': version, 'actor': who,
                     'source': source, 'status': 'requested', 'pair_count': manifest['pair_count'],
                     'setting_count': manifest['setting_count'], 'device_tested': False}
            with self.store.connect() as db:
                self.store.save(db, 'pair_policy_events', event['id'], event)
                self.store.save(db, 'pair_policy_backup', event['id'], current)
            try:
                if self.canonical(current.get('omaSettings', [])) != self.canonical(manifest['policy_body']['omaSettings']):
                    body = {k:manifest['policy_body'][k] for k in ('@odata.type','description','omaSettings')}
                    self.request('PATCH', CONFIG_PATH, body, current.get('@odata.etag'))
                readback = self.read_policy()
                if self.canonical(readback.get('omaSettings', [])) != self.canonical(manifest['policy_body']['omaSettings']):
                    raise PairPolicyError('정책 저장 후 XML 재조회가 일치하지 않습니다.')
                event.update(status='verified', verified_at=utc_stamp())
                with self.store.connect() as db:
                    self.store.save(db, 'pair_policy', 'published', dict(event, policy_id=POLICY_ID))
            except PairPolicyError as error:
                event.update(status='unverified', error=str(error))
                with self.store.connect() as db:
                    self.store.save(db, 'pair_policy_events', event['id'], event)
                raise
            with self.store.connect() as db:
                self.store.save(db, 'pair_policy_events', event['id'], event)
            return event

    def tick(self, source='scheduled-timer'):
        manifest = self.prepare(source)
        with self.store.connect() as db:
            previous = self.store.get(db, 'pair_policy', 'published')
        auto = write_flag('USB_PAIR_POLICY_AUTO_PUBLISH', '.env.pair-policy')
        if self.enabled and auto and (not previous or previous.get('version') != manifest['version']):
            return self.publish(manifest['version'], 'local.pair-policy-worker', source)
        return {'status': 'candidate_ready', 'version': manifest['version'], 'pair_count': manifest['pair_count']}
