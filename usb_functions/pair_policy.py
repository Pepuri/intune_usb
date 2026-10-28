"""Compile explicit sample user/USB pairs into one Intune custom profile.

No Entra user-group condition is emitted. Unmatched access requires the separately
managed Device Control deny baseline; this module never changes that baseline.
"""
import base64
import hashlib
import io
import json
import re
import uuid
import zipfile
import xml.etree.ElementTree as ET
from datetime import datetime, timezone, timedelta

from app.store import ROOT
from app.configuration import deployment_json

_TARGET = deployment_json('USB_SAMPLE_DIRECTORY_JSON', 'sample-tenant-resources.json').get('policy', {})
POLICY_ID = str(uuid.UUID(_TARGET.get('id', '93a76376-be46-5003-8bd5-f90695853547')))
POLICY_NAME = _TARGET.get('name', 'USB-SAMPLE-GROUP-FLOW-20261028')
NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, 'usb-sample-explicit-pairs-20261028')
READ = 9
WRITE = 18


class PairPolicyError(Exception):
    pass


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()).hexdigest()


def guid(value):
    return '{' + str(uuid.uuid5(NAMESPACE, value)) + '}'


def kst_day():
    return datetime.now(timezone(timedelta(hours=9))).date()


def setting(node, kind, label):
    ET.indent(node)
    raw = ET.tostring(node, encoding='utf-8')
    if len(raw) > 65536:  # Conservative local packaging limit, not an asserted Microsoft product limit.
        raise PairPolicyError('XML이 로컬 64KiB 제한을 초과했습니다. 규칙 분할이 필요합니다.')
    token = node.attrib['Id'].replace('{', '%7b').replace('}', '%7d')
    filename = str(uuid.UUID(node.attrib['Id'].strip('{}'))) + '.xml'
    return {'@odata.type': '#microsoft.graph.omaSettingStringXml', 'displayName': 'USB PAIR ' + label,
            'description': 'LAB ONLY: explicit sample user/USB pair; empty target PC group',
            'omaUri': './Vendor/MSFT/Defender/Configuration/DeviceControl/' + kind + '/' + token +
                      ('/GroupData' if kind == 'PolicyGroups' else '/RuleData'),
            'fileName': filename, 'value': base64.b64encode(raw).decode()}


def compile_policy(rows, roster, day=None):
    day = day or kst_day()
    mappings = {r['source_upn'].casefold(): r for r in roster}
    if len(mappings) != 40:
        raise PairPolicyError('샘플 계정 40명의 매핑이 필요합니다.')
    pairs = {}
    excluded = []
    for row in sorted(rows, key=lambda r: r['approval_id']):
        reason = None
        if row['approval_status'] not in ('active', 'deployment_pending'):
            reason = 'ended_or_not_approved'
        elif row['validation_status'] != 'verified':
            reason = 'identity_not_verified'
        elif not row['valid_from_date'] <= day.isoformat() <= row['valid_until_date']:
            reason = 'outside_validity'
        elif row['permission'] == 'read_write' and row.get('bitlocker_state') != 'encrypted':
            reason = 'usb_encryption_not_confirmed'
        if reason:
            excluded.append({'approval_id': row['approval_id'], 'reason': reason})
            continue
        mapped = mappings.get(row['user_upn'].casefold())
        if not mapped or row.get('is_sample') is not True:
            raise PairPolicyError('유효 승인 중 샘플 계정에 매핑되지 않은 사용자가 있습니다: ' + row['approval_id'])
        serial = row['usb_serial'].upper()
        if not re.fullmatch(r'SAMPLE-[A-Z0-9-]{1,93}', serial):
            raise PairPolicyError('실제 USB 식별값은 이 샘플 게시 경로에서 사용할 수 없습니다.')
        if row['permission'] not in ('read', 'read_only', 'read_write'):
            raise PairPolicyError('지원하지 않는 USB 권한입니다.')
        oid = str(uuid.UUID(mapped['object_id']))
        key = (oid, serial)
        pair = pairs.setdefault(key, {'user_object_id': oid, 'user_upn': mapped['upn'], 'name': mapped['name'],
                    'usb_serial': serial, 'permission': 'read_only', 'approval_ids': [], 'valid_until_dates': []})
        pair['approval_ids'].append(row['approval_id'])
        pair['valid_until_dates'].append(row['valid_until_date'])
        if row['permission'] == 'read_write':
            pair['permission'] = 'read_write'
    ordered = [pairs[k] for k in sorted(pairs)]
    serials = sorted({p['usb_serial'] for p in ordered})
    settings = []
    encrypted_id = guid('media/bitlocker-encrypted')
    if any(p['permission'] == 'read_write' for p in ordered):
        encrypted = ET.Element('Group', Id=encrypted_id, Type='Device')
        ET.SubElement(encrypted, 'Name').text = 'USB PAIR BitLocker encrypted removable media'
        ET.SubElement(encrypted, 'MatchType').text = 'MatchAll'
        desc = ET.SubElement(encrypted, 'DescriptorIdList')
        ET.SubElement(desc, 'PrimaryId').text = 'RemovableMediaDevices'
        ET.SubElement(desc, 'DeviceEncryptionStateId').text = 'BitlockerEncrypted'
        settings.append(setting(encrypted, 'PolicyGroups', 'encrypted media'))
    for serial in serials:
        gid = guid('media/' + serial)
        media = ET.Element('Group', Id=gid, Type='Device')
        ET.SubElement(media, 'Name').text = 'USB PAIR ' + serial
        ET.SubElement(media, 'MatchType').text = 'MatchAll'
        desc = ET.SubElement(media, 'DescriptorIdList')
        ET.SubElement(desc, 'PrimaryId').text = 'RemovableMediaDevices'
        ET.SubElement(desc, 'SerialNumberId').text = serial
        settings.append(setting(media, 'PolicyGroups', serial))
        matched = [p for p in ordered if p['usb_serial'] == serial]
        for mode, mask, selected in [('read', READ, matched),
                                      ('write', WRITE, [p for p in matched if p['permission'] == 'read_write'])]:
            if not selected:
                continue
            rule = ET.Element('PolicyRule', Id=guid('rule/' + serial + '/' + mode))
            ET.SubElement(rule, 'Name').text = 'USB PAIR ' + serial + ' ' + mode
            included = ET.SubElement(rule, 'IncludedIdList')
            ET.SubElement(included, 'GroupId').text = gid
            if mode == 'write':
                ET.SubElement(included, 'GroupId').text = encrypted_id
            ET.SubElement(rule, 'ExcludedIdList')
            for p in selected:
                for action, option in [('Allow', 0), ('AuditAllowed', 2)]:
                    entry = ET.SubElement(rule, 'Entry', Id=guid('entry/' + serial + '/' + mode + '/' + p['user_object_id'] + '/' + action))
                    ET.SubElement(entry, 'Type').text = action
                    ET.SubElement(entry, 'Options').text = str(option)
                    ET.SubElement(entry, 'AccessMask').text = str(mask)
                    ET.SubElement(entry, 'Sid').text = p['user_object_id']
            settings.append(setting(rule, 'PolicyRules', serial + ' ' + mode))
    if len(settings) > 1000:
        raise PairPolicyError('단일 Intune Custom 정책의 OMA 설정 1000개 한도를 초과했습니다.')
    body = {'@odata.type': '#microsoft.graph.windows10CustomConfiguration', 'displayName': POLICY_NAME,
            'description': 'LAB ONLY | Explicit user-USB pairs. Empty PC target. Individual Entra object IDs. '
                           'Requires separate Device Control enabled/default-deny baseline; endpoint behavior untested.',
            'omaSettings': settings}
    manifest = {'format': 'usb-explicit-pairs-v1', 'policy_id': POLICY_ID, 'policy_name': POLICY_NAME,
                'reference_date': day.isoformat(), 'pairs': ordered, 'excluded': excluded,
                'pair_count': len(ordered), 'usb_count': len(serials),
                'user_count': len({p['user_object_id'] for p in ordered}), 'setting_count': len(settings),
                'identity_mode': 'entra_user_object_id', 'sid_lookup_assumed': True,
                'default_deny_baseline_required': True, 'baseline_verified': False,
                'usb_encryption_descriptor_preview': any(p['permission'] == 'read_write' for p in ordered),
                'device_tested': False, 'group_membership_used_for_pair_permissions': False, 'policy_body': body}
    manifest['version'] = digest(manifest)
    validate_manifest(manifest)
    return manifest


def evaluate_xml(settings, oid, serial, operation, encrypted=False, _parsed=None):
    """Local XML semantics check only, under the explicitly assumed deny baseline."""
    serial = serial.upper()
    if _parsed is None:
        groups = {}
        rules = []
        for item in settings:
            node = ET.fromstring(base64.b64decode(item['value']))
            if node.tag == 'Group':
                groups[node.attrib['Id']] = node
            else:
                rules.append(node)
    else:
        groups, rules = _parsed
    matching = set()
    for gid, group in groups.items():
        props = {r.tag: r.text for r in group.find('DescriptorIdList')}
        if (props.get('PrimaryId') == 'RemovableMediaDevices' and
                props.get('SerialNumberId', serial) == serial and
                ('DeviceEncryptionStateId' not in props or encrypted)):
            matching.add(gid)
    required = {'read': READ, 'write': WRITE, 'execute': 36}[operation]
    allowed = 0
    for rule in rules:
        if not {n.text for n in rule.findall('IncludedIdList/GroupId')} <= matching:
            continue
        for entry in rule.findall('Entry'):
            if entry.findtext('Type') == 'Allow' and entry.findtext('Sid') == oid:
                allowed |= int(entry.findtext('AccessMask'))
    return (allowed & required) == required


def validate_manifest(manifest):
    settings = manifest['policy_body']['omaSettings']
    ids = []
    parsed_groups = {}
    parsed_rules = []
    xml_users = set()
    xml_serials = set()
    for item in settings:
        node = ET.fromstring(base64.b64decode(item['value']))
        if node.tag == 'Group':
            parsed_groups[node.attrib['Id']] = node
            if node.findtext('SerialNumberId'):
                xml_serials.add(node.findtext('SerialNumberId'))
            if node.findtext('MatchType') != 'MatchAll':
                raise PairPolicyError('USB 매칭은 MatchAll만 사용할 수 있습니다.')
            xml_serials.update(n.text for n in node.findall('DescriptorIdList/SerialNumberId'))
        elif node.tag == 'PolicyRule':
            parsed_rules.append(node)
            xml_users.update(n.text for n in node.findall('Entry/Sid'))
            if not node.findall('IncludedIdList/GroupId'):
                raise PairPolicyError('USB 조건 없는 규칙은 허용하지 않습니다.')
        else:
            raise PairPolicyError('지원하지 않는 XML입니다.')
        ids.extend([n.attrib['Id'] for n in node.iter() if 'Id' in n.attrib])
        token = node.attrib['Id'].replace('{', '%7b').replace('}', '%7d')
        if '/' + token + '/' not in item['omaUri']:
            raise PairPolicyError('XML ID와 OMA 경로가 일치하지 않습니다.')
    if len(ids) != len(set(ids)) or len(settings) != len({s['omaUri'] for s in settings}):
        raise PairPolicyError('XML 또는 OMA ID가 중복됩니다.')
    by_pair = {(p['user_object_id'], p['usb_serial']): p for p in manifest['pairs']}
    users = sorted({p['user_object_id'] for p in manifest['pairs']} | xml_users) + ['00000000-0000-0000-0000-000000000000']
    serials = sorted({p['usb_serial'] for p in manifest['pairs']} | xml_serials) + ['SAMPLE-UNAPPROVED-USB']
    # Exhaustively compare every user x every USB, including negative crosses.
    checks = 0
    for user in users:
        for serial in serials:
            pair = by_pair.get((user, serial))
            for operation, encrypted in [('read', False), ('write', False), ('write', True), ('execute', True)]:
                expected = bool(pair and (operation == 'read' or
                                (operation == 'write' and encrypted and pair['permission'] == 'read_write')))
                if evaluate_xml(settings, user, serial, operation, encrypted, (parsed_groups, parsed_rules)) != expected:
                    raise PairPolicyError('사용자–USB 교차 허용 검증에 실패했습니다.')
                checks += 1
    manifest['matrix_checks'] = checks


def package_bytes(manifest):
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('manifest.json', json.dumps(manifest, ensure_ascii=False, indent=2))
        archive.writestr('policy-patch.json', json.dumps(manifest['policy_body'], ensure_ascii=False, indent=2))
        for item in manifest['policy_body']['omaSettings']:
            archive.writestr('xml/' + item['fileName'], base64.b64decode(item['value']))
    return output.getvalue()
