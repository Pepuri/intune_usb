"""Local lab group membership only. The Intune publisher remains mock."""
import json
import threading
import time
import uuid
from datetime import datetime, timezone, timedelta

import httpx
from dotenv import dotenv_values

from app.store import ROOT
from app.runtime import write_flag
from app.configuration import deployment_json
from .read_sources import AppTokens, SourceError

DEFAULT_CONFIG = deployment_json('USB_SAMPLE_DIRECTORY_JSON', 'sample-tenant-resources.json')
TENANT = str(uuid.UUID(DEFAULT_CONFIG['tenant_id']))
USERS = str(uuid.UUID(DEFAULT_CONFIG['user_group']['id']))
PCS = str(uuid.UUID(DEFAULT_CONFIG['device_group']['id']))
DOMAIN = DEFAULT_CONFIG['users'][0]['upn'].rsplit('@', 1)[1]
GRAPH = 'https://graph.microsoft.com/v1.0'
LAB_LOCK = threading.RLock()


def utc_stamp():
    return datetime.now(timezone.utc).isoformat()


class LabError(Exception):
    pass


class SampleDirectory:
    def __init__(self, store, tenant_id, *, config=None, tokens=None, transport=None, enabled=None, today=None):
        self.store = store
        self.config = config if config is not None else deployment_json(
            'USB_SAMPLE_DIRECTORY_JSON', 'sample-tenant-resources.json')
        if tenant_id != TENANT or self.config.get('tenant_id') != TENANT:
            raise LabError('샘플 테넌트가 일치하지 않습니다.')
        if self.config['user_group']['id'] != USERS or self.config['device_group']['id'] != PCS:
            raise LabError('허용된 샘플 그룹 ID가 아닙니다.')
        self.users = {r['source_approval_id']: r for r in self.config['users']}
        if len(self.users) != 40 or len({r['object_id'] for r in self.users.values()}) != 40:
            raise LabError('샘플 계정 40명의 매핑을 확인해 주세요.')
        for i, r in enumerate(self.config['users'], 1):
            if r['upn'] != f'usb.sample{i:03d}@{DOMAIN}':
                raise LabError('샘플 계정 허용 목록이 올바르지 않습니다.')
            uuid.UUID(r['object_id'])
        self.tokens = tokens or AppTokens(TENANT)
        self.transport = transport
        self._enabled = enabled
        # KST is UTC+09:00; Windows Python may not ship an IANA timezone database.
        self.today = today or (lambda: datetime.now(timezone(timedelta(hours=9))).date())
        self.lock = LAB_LOCK

    @property
    def enabled(self):
        if self._enabled is not None:
            return self._enabled
        return write_flag('USB_SAMPLE_GROUP_WRITES', '.env.sample-directory')

    def request(self, method, path, body=None):
        allowed_reads = {
            f'/groups/{g}' for g in (USERS, PCS)
        } | {f'/groups/{g}/members' for g in (USERS, PCS)} | {
            '/users/' + r['object_id'] for r in self.users.values()
        }
        allowed_writes = {('POST', f'/groups/{USERS}/members/$ref')} | {
            ('DELETE', f'/groups/{USERS}/members/{r["object_id"]}/$ref') for r in self.users.values()
        }
        if not ((method == 'GET' and path in allowed_reads) or
                (self.enabled and (method, path) in allowed_writes)):
            raise LabError('허용된 샘플 그룹 경로만 사용할 수 있습니다.')
        if method == 'POST' and body not in [
                {'@odata.id': GRAPH + '/directoryObjects/' + r['object_id']} for r in self.users.values()]:
            raise LabError('샘플 계정만 그룹에 추가할 수 있습니다.')
        params = None
        if method == 'GET':
            if path.endswith('/members'):
                params = {'$select': 'id', '$top': '999'}
            elif path.startswith('/users/'):
                params = {'$select': 'id,userPrincipalName,accountEnabled,assignedLicenses,employeeId'}
            else:
                params = {'$select': 'id,displayName,description,securityEnabled,mailEnabled,groupTypes,isAssignableToRole'}
        try:
            token = self.tokens.token('https://graph.microsoft.com')
            with httpx.Client(transport=self.transport, timeout=10, follow_redirects=False) as client:
                response = client.request(method, GRAPH + path, params=params, json=body,
                                          headers={'Authorization': 'Bearer ' + token})
            if not response.is_success:
                raise LabError(f'Graph HTTP {response.status_code} · 그룹 멤버 권한과 연결 상태를 확인해 주세요.')
            return response.json() if response.content else {}
        except (SourceError, httpx.RequestError):
            raise LabError('Graph 인증 또는 연결을 확인해 주세요.') from None

    def members(self, group):
        data = self.request('GET', f'/groups/{group}/members')
        if data.get('@odata.nextLink'):
            raise LabError('그룹 조회가 완전하지 않아 작업을 중단했습니다.')
        return {r['id'] for r in data['value']}

    def preflight(self):
        for group, name in ((USERS, 'USB-SAMPLE-USERS-20261028'), (PCS, 'USB-SAMPLE-PCS-20261028')):
            r = self.request('GET', '/groups/' + group)
            if (r.get('id') != group or r.get('displayName') != name or not r.get('securityEnabled')
                    or r.get('mailEnabled') or r.get('groupTypes') or r.get('isAssignableToRole')
                    or 'USB_SAMPLE_FLOW_20261028' not in (r.get('description') or '')):
                raise LabError('정적 샘플 보안 그룹인지 확인하지 못했습니다.')
        if self.members(PCS):
            raise LabError('테스트 PC 그룹이 비어 있지 않아 그룹 변경을 중단했습니다.')
        members = self.members(USERS)
        if not members <= {r['object_id'] for r in self.users.values()}:
            raise LabError('허용 목록 외 그룹 멤버가 있어 작업을 중단했습니다.')
        return members

    def status(self):
        with self.store.connect() as db:
            grants = {r['approval_id']: r for r in self.store.rows(db, 'sample_grants')}
            history = sorted(self.store.rows(db, 'sample_group_history'), key=lambda r: r['at'], reverse=True)[:30]
        try:
            members = self.preflight()
            live = {'status': 'ok', 'user_member_count': len(members), 'device_member_count': 0}
        except LabError as e:
            members = None
            live = {'status': 'unavailable', 'detail': str(e)}
        return {'enabled': self.enabled, 'tenant_id': TENANT, 'user_group_id': USERS, 'device_group_id': PCS,
                'user_group_name': self.config['user_group']['name'], 'policy': self.config.get('policy'),
                'mode': 'sample_group_only', 'intune_policy_changed': False, 'device_confirmed': False,
                'live': live, 'users': [dict(r, member=(r['object_id'] in members) if members is not None else None,
                    grant=grants.get(k), sid_lookup={
                        'mode': 'assumed', 'verified': False,
                        'value': f'S-1-5-21-1111111111-2222222222-3333333333-{1001+i}',
                        'used_for_graph_or_policy': False}) for i, (k, r) in enumerate(self.users.items())], 'history': history}

    def change(self, key, action, until, reason, who, *, source='manual-api', expected_event=None):
        if not self.enabled:
            raise LabError('샘플 그룹 쓰기는 비활성 상태입니다. 권한 승인 후 활성화해야 합니다.')
        if key not in self.users or action not in ('approve', 'revoke', 'expire'):
            raise LabError('허용된 샘플 사용자 작업이 아닙니다.')
        row = self.users[key]
        if action == 'approve' and (until is None or until < self.today()):
            raise LabError('종료일은 현재 날짜 이후여야 합니다.')
        with self.lock, self.store.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            prior = self.store.get(db, 'sample_grants', key)
            if expected_event is not None and (not prior or prior.get('event_id') != expected_event):
                return {'approval_id': key, 'status': 'superseded'}
            if action == 'expire' and (not prior or prior['state'] not in ('approved', 'approved_pending', 'expire_pending')
                                      or prior['valid_until_date'] >= self.today().isoformat()):
                return {'approval_id': key, 'status': 'superseded'}
            members = self.preflight()
            user = self.request('GET', '/users/' + row['object_id'])
            index = list(self.users).index(key) + 1
            if (user.get('id') != row['object_id'] or user.get('userPrincipalName') != row['upn']
                    or user.get('accountEnabled') is not False or user.get('assignedLicenses') != []
                    or user.get('employeeId') != f'USBS261028-{index:03d}'):
                raise LabError('비활성·무라이선스 샘플 계정 검증에 실패했습니다.')
            present = row['object_id'] in members
            desired = action == 'approve'
            receipt = {'event_id': uuid.uuid4().hex, 'approval_id': key, 'upn': row['upn'], 'action': action,
                       'actor': who, 'reason': reason, 'at': utc_stamp(), 'source': source,
                       'before_member': present, 'desired_member': desired, 'status': 'requested',
                       'valid_until_date': until.isoformat() if until else None, 'device_confirmed': False}
            # Commit the intent before the external side effect. A crash is shown as requested, never success.
            self.store.save(db, 'sample_group_history', receipt['event_id'], receipt)
            self.store.save(db, 'sample_grants', key, {
                'approval_id': key, 'state': 'approved_pending' if desired else action + '_pending',
                'valid_until_date': until.isoformat() if until else (prior or {}).get('valid_until_date'),
                'updated_at': utc_stamp(), 'member': None, 'event_id': receipt['event_id']})
            db.commit()
            try:
                if present != desired:
                    if desired:
                        self.request('POST', f'/groups/{USERS}/members/$ref',
                                     {'@odata.id': GRAPH + '/directoryObjects/' + row['object_id']})
                    else:
                        self.request('DELETE', f'/groups/{USERS}/members/{row["object_id"]}/$ref')
                after = row['object_id'] in self.members(USERS)
                for delay in (1, 2, 4):
                    if after == desired:
                        break
                    time.sleep(delay)
                    after = row['object_id'] in self.members(USERS)
                if after != desired:
                    raise LabError('Graph 반영 확인 대기 상태입니다. 새로고침 후 같은 작업을 재시도해 주세요.')
                receipt.update(status='verified', after_member=after)
                grant = {'approval_id': key, 'state': 'approved' if desired else action,
                         'valid_until_date': until.isoformat() if until else None, 'updated_at': utc_stamp(),
                         'member': after, 'event_id': receipt['event_id']}
                self.store.save(db, 'sample_grants', key, grant)
            except LabError as error:
                receipt.update(status='unverified', error=str(error))
                self.store.save(db, 'sample_group_history', receipt['event_id'], receipt)
                db.commit()
                raise
            self.store.save(db, 'sample_group_history', receipt['event_id'], receipt)
            return receipt

    def expire(self, source='scheduled-timer'):
        if not self.enabled:
            return {'enabled': False, 'outcomes': []}
        with self.store.connect() as db:
            linked = {r['sample_key'] for r in self.store.rows(db, 'sample_ledger_links') if r.get('active', True)}
            expired = [r for r in self.store.rows(db, 'sample_grants') if r['state'] in ('revoke_pending', 'expire_pending')
                       or (r['state'] in ('approved', 'approved_pending') and r['valid_until_date'] < self.today().isoformat())]
            expired = [r for r in expired if r['approval_id'] not in linked]
        outcomes = []
        for row in expired:
            try:
                action = 'revoke' if row['state'] == 'revoke_pending' else 'expire'
                result = self.change(row['approval_id'], action, None, '샘플 승인 기간 만료 또는 미완료 회수 재시도',
                                     'local.sample-expiry', source=source, expected_event=row['event_id'])
                outcomes.append(result)
            except LabError as e:
                outcomes.append({'approval_id': row['approval_id'], 'status': 'unverified', 'error': str(e)})
        return {'enabled': True, 'outcomes': outcomes}
