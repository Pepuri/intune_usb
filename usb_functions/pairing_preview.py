"""PPT pairing model. Local ledger and XML compiler; deliberately has no Graph client."""
import base64
import io
import json
import uuid
import zipfile
import xml.etree.ElementTree as ET
from datetime import date

from pydantic import BaseModel, ConfigDict, Field, model_validator
from .pair_policy import PairPolicyError, digest, guid, setting

PREFIX = './Vendor/MSFT/Defender/Configuration/'


class PairingInput(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)
    user_object_id: uuid.UUID
    device_type: str = Field(pattern=r'^(usb|mtp)$')
    identifier: str = Field(min_length=1, max_length=1024)
    valid_from_date: date
    valid_until_date: date
    identity_verified: bool = False

    @model_validator(mode='after')
    def validate_pair(self):
        if self.user_object_id.int == 0 or self.valid_until_date < self.valid_from_date:
            raise ValueError('사용자 Object ID와 허용 기간을 확인하세요.')
        if any(ord(c) < 32 or ord(c) == 127 or c in '*?;' for c in self.identifier):
            raise ValueError('정확한 단일 식별값만 입력할 수 있습니다. 와일드카드는 지원하지 않습니다.')
        if self.device_type == 'mtp' and '\\' not in self.identifier:
            raise ValueError('MTP는 전체 InstancePathId가 필요합니다.')
        return self


def evaluate(settings, user, device_type, identifier, mask=63):
    """Evaluate the supported generated subset, under its default-deny baseline."""
    groups, rules = {}, []
    for item in settings:
        if not item['@odata.type'].endswith('omaSettingStringXml'):
            continue
        node = ET.fromstring(base64.b64decode(item['value'], validate=True))
        if node.tag == 'Group':
            desc = node.find('DescriptorIdList')
            expected = {'PrimaryId': 'RemovableMediaDevices' if device_type == 'usb' else 'WpdDevices',
                        'SerialNumberId' if device_type == 'usb' else 'InstancePathId': identifier}
            groups[node.attrib['Id']] = (node.findtext('MatchType') == 'MatchAll' and desc is not None
                and len(desc) == 2 and all(expected.get(n.tag, '').casefold() == (n.text or '').casefold() for n in desc))
        elif node.tag == 'PolicyRule':
            rules.append(node)
    allowed = 0
    for rule in rules:
        includes = rule.findall('IncludedIdList/GroupId')
        if not includes or not all(groups.get(n.text, False) for n in includes):
            continue
        for entry in rule.findall('Entry'):
            if entry.findtext('Type') == 'Allow' and entry.findtext('Sid') == str(user):
                allowed |= int(entry.findtext('AccessMask', '0'))
    return allowed & mask == mask


def compile_pairing(rows, day=None):
    day = day or date.today()
    pairs, excluded = {}, []
    for row in sorted(rows, key=lambda r: r['id']):
        value = PairingInput.model_validate({k: row[k] for k in PairingInput.model_fields})
        reason = (row['status'] if row.get('status') in ('revoked', 'expired', 'rejected') else 'identity_not_verified' if not value.identity_verified
                  else 'outside_validity' if not value.valid_from_date <= day <= value.valid_until_date else None)
        if reason:
            excluded.append({'id': row['id'], 'reason': reason})
            continue
        key = (str(value.user_object_id), value.device_type, value.identifier.casefold())
        pairs.setdefault(key, {'user_object_id': key[0], 'device_type': key[1], 'identifier': value.identifier, 'approval_ids': []})['approval_ids'].append(row['id'])
    settings = []
    for name, typ, value in [('DeviceControlEnabled', 'Integer', 1), ('DefaultEnforcement', 'Integer', 2),
                             ('SecuredDevicesConfiguration', 'String', 'RemovableMediaDevices|WpdDevices')]:
        settings.append({'@odata.type': '#microsoft.graph.omaSetting'+typ, 'displayName': name,
                         'omaUri': PREFIX+name, 'value': value})
    devices = sorted({(p['device_type'], p['identifier'].casefold()) for p in pairs.values()})
    if 3 + 2 * len(devices) > 1000:
        raise PairPolicyError('단일 정책의 OMA 설정 1000개 제한을 초과했습니다.')
    for family, identifier in devices:
        semantic = 'ppt-v2:' + family + ':' + identifier
        group_id = guid(semantic+':group')
        group = ET.Element('Group', {'Id': group_id, 'Type': 'Device'})
        ET.SubElement(group, 'Name').text = family.upper()+' explicit pairing'
        ET.SubElement(group, 'MatchType').text = 'MatchAll'
        desc = ET.SubElement(group, 'DescriptorIdList')
        ET.SubElement(desc, 'PrimaryId').text = 'RemovableMediaDevices' if family == 'usb' else 'WpdDevices'
        ET.SubElement(desc, 'SerialNumberId' if family == 'usb' else 'InstancePathId').text = identifier
        settings.append(setting(group, 'PolicyGroups', family+' device'))
        rule = ET.Element('PolicyRule', {'Id': guid(semantic+':rule')})
        ET.SubElement(rule, 'Name').text = family.upper()+' authorized users'
        ET.SubElement(ET.SubElement(rule, 'IncludedIdList'), 'GroupId').text = group_id
        ET.SubElement(rule, 'ExcludedIdList')
        for user in sorted({p['user_object_id'] for p in pairs.values() if p['device_type'] == family and p['identifier'].casefold() == identifier}):
            for kind, options in [('Allow', '0'), ('AuditAllowed', '2')]:
                entry = ET.SubElement(rule, 'Entry', {'Id': guid(semantic+':'+user+':'+kind)})
                for key, val in [('Type', kind), ('Options', options), ('AccessMask', '63'), ('Sid', user)]:
                    ET.SubElement(entry, key).text = val
        settings.append(setting(rule, 'PolicyRules', family+' pair'))
    if len(settings) > 1000:
        raise PairPolicyError('단일 정책의 OMA 설정 1000개 제한을 초과했습니다.')
    manifest = {'format': 'usb-mtp-pairs-v2', 'local_only': True, 'writes_enabled': False,
                'assignment_group_count': 1, 'policy_count': 1, 'assignment_target_type': 'device_group',
                'reference_date': day.isoformat(), 'pair_count': len(pairs), 'device_count': len(devices),
                'pairs': list(pairs.values()), 'excluded': excluded, 'setting_count': len(settings),
                'access_mask': 63, 'bitlocker_required': False, 'device_tested': False,
                'identity_source': 'manual_local_assumption',
                'policy_body': {'@odata.type': '#microsoft.graph.windows10CustomConfiguration', 'omaSettings': settings}}
    validate_pairing(manifest)
    manifest['version'] = digest(manifest)
    return manifest


def validate_pairing(manifest):
    settings = manifest['policy_body']['omaSettings']
    expected_baseline = {'DeviceControlEnabled': 1, 'DefaultEnforcement': 2,
                         'SecuredDevicesConfiguration': 'RemovableMediaDevices|WpdDevices'}
    baseline = {s['omaUri'].removeprefix(PREFIX): s['value'] for s in settings if 'fileName' not in s}
    if baseline != expected_baseline or not manifest.get('local_only') or manifest.get('writes_enabled'):
        raise PairPolicyError('로컬 전용 기본 차단 설정이 일치하지 않습니다.')
    pairs = {(p['user_object_id'], p['device_type'], p['identifier'].casefold()) for p in manifest['pairs']}
    ids, uris = [], []
    for item in settings:
        uris.append(item['omaUri'].casefold())
        if item['@odata.type'].endswith('omaSettingStringXml'):
            node = ET.fromstring(base64.b64decode(item['value'], validate=True))
            if node.tag == 'PolicyRule':
                if node.findall('ExcludedIdList/*') or len(node.findall('IncludedIdList/GroupId')) != 1:
                    raise PairPolicyError('단일 장치 조건만 지원합니다.')
                for entry in node.findall('Entry'):
                    kind = entry.findtext('Type')
                    if (kind not in ('Allow', 'AuditAllowed') or entry.findtext('AccessMask') != '63'
                        or entry.findtext('Options') != ('0' if kind == 'Allow' else '2')
                        or len(entry.findall('Sid')) != 1 or len(entry) != 4):
                        raise PairPolicyError('지원하지 않는 페어링 Entry입니다.')
            ids.extend(n.attrib['Id'] for n in node.iter() if 'Id' in n.attrib)
            if node.attrib['Id'].replace('{', '%7b').replace('}', '%7d').casefold() not in item['omaUri'].casefold():
                raise PairPolicyError('XML ID와 OMA 경로 불일치')
    if len(ids) != len(set(ids)) or len(uris) != len(set(uris)):
        raise PairPolicyError('중복된 XML/OMA ID')
    checks = 0
    users = {p[0] for p in pairs} | {str(uuid.UUID(int=0))}
    devices = {(p[1], p[2]) for p in pairs} | {('usb', 'unapproved'), ('mtp', 'usb\\unapproved')}
    for user in users:
        for family, identifier in devices:
            for mask in (1, 2, 4, 8, 16, 32, 63):
                if evaluate(settings, user, family, identifier, mask) != ((user, family, identifier) in pairs):
                    raise PairPolicyError('사용자–장치 교차 권한 검증 실패')
                checks += 1
    manifest['matrix_checks'] = checks


def package(manifest):
    result = io.BytesIO()
    with zipfile.ZipFile(result, 'w', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('LOCAL-PREVIEW-ONLY.txt', 'No tenant changes. Do not upload without separate deployment review.')
        archive.writestr('manifest.json', json.dumps(manifest, ensure_ascii=False, indent=2))
        for item in manifest['policy_body']['omaSettings']:
            if 'fileName' in item:
                archive.writestr('xml/'+item['fileName'], base64.b64decode(item['value']))
    return result.getvalue()


def approval_pairings(store, db):
    """Read the existing approval ledger without copying it to a second ledger."""
    return [dict(id=r['approval_id'], user_object_id=r['user_object_id'],
                 device_type=r['device_type'], identifier=r['usb_serial'],
                 valid_from_date=r['valid_from_date'], valid_until_date=r['valid_until_date'],
                 identity_verified=r['validation_status'] == 'verified',
                 status=r['approval_status'],
                 user_display_name=r['user_display_name'], user_upn=r['user_upn'],
                 approval_status=r['approval_status'], deployment_status=r['deployment_status'])
            for r in store.rows(db, 'approvals') if r.get('policy_mode') == 'usb_mtp_pairing']


def install_local_routes(app, store, today):
    from fastapi import HTTPException
    from fastapi.responses import Response, JSONResponse

    @app.exception_handler(PairPolicyError)
    async def invalid_candidate(request, error):
        return JSONResponse({'detail': str(error)}, status_code=409)

    def preview():
        from app.runtime import cloud_mode
        if cloud_mode():
            raise HTTPException(403, '독립 실험 원장은 로컬 전용입니다. 승인 등록 화면을 사용하세요.')
        with store.connect() as db:
            rows = store.rows(db, 'ppt_pairings')
        return dict(compile_pairing(rows, today()), ledger=rows)

    app.get('/api/pairing-lab')(preview)

    @app.get('/api/pairing-policy')
    def ledger_preview():
        with store.connect() as db:
            rows = approval_pairings(store, db)
        return dict(compile_pairing(rows, today()), ledger=rows, ledger_source='approvals')

    @app.get('/api/pairing-policy/package.zip')
    def ledger_package():
        return Response(package(ledger_preview()), media_type='application/zip',
                        headers={'Content-Disposition': 'attachment; filename="usb-mtp-local-preview.zip"'})

    @app.post('/api/pairing-policy/publish')
    def ledger_publish():
        raise HTTPException(403, '원장 연결은 로컬 미리보기 전용입니다. 실제 정책 반영은 비활성입니다.')

    @app.post('/api/pairing-lab')
    def register(body: PairingInput):
        from app.runtime import cloud_mode
        if cloud_mode():
            raise HTTPException(403, '독립 실험 원장은 로컬 전용입니다.')
        row = dict(body.model_dump(mode='json'), id=str(uuid.uuid4()), status='active')
        with store.connect() as db:
            rows = store.rows(db, 'ppt_pairings')
            compile_pairing(rows+[row], today())  # Validate package limits before committing.
            store.save(db, 'ppt_pairings', row['id'], row)
        return row

    @app.post('/api/pairing-lab/{key}/revoke')
    def revoke(key: str):
        from app.runtime import cloud_mode
        if cloud_mode():
            raise HTTPException(403, '독립 실험 원장은 로컬 전용입니다.')
        with store.connect() as db:
            row = store.get(db, 'ppt_pairings', key)
            if not row:
                raise HTTPException(404, '페어링 원장이 없습니다.')
            row['status'] = 'revoked'
            store.save(db, 'ppt_pairings', key, row)
        return row

    @app.get('/api/pairing-lab/package.zip')
    def download():
        return Response(package(preview()), media_type='application/zip')

    @app.post('/api/pairing-lab/publish')
    def publish():
        raise HTTPException(403, '로컬 검증 전용입니다. 실제 정책 반영은 비활성입니다.')
