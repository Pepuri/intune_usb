import base64
import copy
import json
import uuid
from datetime import date
import xml.etree.ElementTree as ET

import pytest
from fastapi.testclient import TestClient
from app.store import Store
from usb_functions.api import create_business_api
from usb_functions.bridge import sign_request
from usb_functions.pairing_preview import compile_pairing, evaluate, validate_pairing, PairingInput
from usb_functions.pair_policy import PairPolicyError

DAY = date(2026, 10, 28)
U1, U2 = str(uuid.UUID(int=1)), str(uuid.UUID(int=2))


def row(user=U1, family='usb', identifier='SAMPLE-USB-A', **kw):
    return dict(id=str(uuid.uuid4()), user_object_id=user, device_type=family, identifier=identifier,
                valid_from_date='2026-10-01', valid_until_date='2026-11-30', identity_verified=True,
                status='active', **kw)


def test_usb_mtp_explicit_relations_not_cartesian():
    rows = [row(), row(U1, 'mtp', r'USB\VID_1234&PID_5678\SAMPLE-MTP'), row(U2, identifier='SAMPLE-USB-B')]
    m = compile_pairing(rows, DAY)
    settings = m['policy_body']['omaSettings']
    assert m['policy_count'] == m['assignment_group_count'] == 1
    assert m['setting_count'] == 9 and m['pair_count'] == 3
    assert not m['writes_enabled'] and m['local_only'] and not m['bitlocker_required']
    assert m['matrix_checks'] == 105
    assert evaluate(settings, U1, 'usb', 'sample-usb-a')
    assert evaluate(settings, U1, 'mtp', rows[1]['identifier'])
    assert not evaluate(settings, U1, 'usb', 'SAMPLE-USB-B')
    assert not evaluate(settings, U2, 'mtp', rows[1]['identifier'])
    assert not evaluate(settings, U1, 'mtp', 'SAMPLE-USB-A')
    assert settings[2]['value'] == 'RemovableMediaDevices|WpdDevices'
    raw = '\n'.join(base64.b64decode(s['value']).decode() for s in settings if 'fileName' in s)
    assert 'Bitlocker' not in raw and '&amp;' in raw
    ids = [n.attrib['Id'] for s in settings if 'fileName' in s for n in ET.fromstring(base64.b64decode(s['value'])).iter() if 'Id' in n.attrib]
    assert len(ids) == len(set(ids))


def test_revocation_expiry_unverified_duplicates_and_stable_version():
    rows = [row(), row()]
    m = compile_pairing(rows, DAY)
    assert m['pair_count'] == 1 and m['setting_count'] == 5
    assert compile_pairing(list(reversed(rows)), DAY)['version'] == m['version']
    for overrides in [{'status': 'revoked'}, {'identity_verified': False}, {'valid_until_date': '2026-10-27'}, {'valid_from_date': '2026-10-29'}]:
        excluded = compile_pairing([rows[0] | overrides], DAY)
        assert excluded['pair_count'] == 0 and excluded['setting_count'] == 3


@pytest.mark.parametrize('family,identifier', [('mtp', 'short'), ('usb', '*'), ('usb', 'ABC;DEF'), ('mtp', 'USB\\bad\npath')])
def test_reject_unsafe_or_incomplete_identifier(family, identifier):
    with pytest.raises(ValueError):
        compile_pairing([row(family=family, identifier=identifier)], DAY)


def test_xml_tamper_cannot_grant_other_user():
    m = compile_pairing([row()], DAY)
    bad = copy.deepcopy(m)
    rule = bad['policy_body']['omaSettings'][-1]
    node = ET.fromstring(base64.b64decode(rule['value']))
    node.find('Entry/Sid').text = U2
    rule['value'] = base64.b64encode(ET.tostring(node)).decode()
    with pytest.raises(PairPolicyError):
        validate_pairing(bad)


def test_single_policy_limit_rejected_before_building_large_matrix():
    with pytest.raises(PairPolicyError, match='1000'):
        compile_pairing([row(identifier=f'SAMPLE-USB-{i}') for i in range(499)], DAY)


def test_authenticated_api_persistence_revoke_and_publish_blocked(tmp_path, monkeypatch):
    monkeypatch.setenv('USB_PAIR_POLICY_WRITES', '1')
    monkeypatch.setenv('USB_PAIR_POLICY_AUTO_PUBLISH', '1')
    key = 'test-bridge-key-' * 5
    db = tmp_path/'local.sqlite3'
    client = TestClient(create_business_api(db_path=db, bridge_key=key, allow_demo=True))
    user = {'source': 'demo', 'username': 'test@example.invalid', 'roles': ['USB.Operator']}
    def call(method, path, data=None):
        body = json.dumps(data).encode() if data is not None else b''
        return client.request(method, path, content=body, headers={'content-type':'application/json', 'x-usb-assertion':sign_request(key, user, method, path, body)})
    assert client.get('/api/pairing-lab').status_code == 401
    data = {k:v for k,v in row().items() if k in PairingInput.model_fields}
    saved = call('POST', '/api/pairing-lab', data)
    assert saved.status_code == 200, saved.text
    assert call('GET', '/api/pairing-lab').json()['pair_count'] == 1
    assert call('GET', '/api/pairing-lab/package.zip').status_code == 200
    assert call('POST', '/api/pairing-lab/publish', {}).status_code == 403
    assert call('POST', '/api/pairing-lab/'+saved.json()['id']+'/revoke', {}).status_code == 200
    assert call('GET', '/api/pairing-lab').json()['pair_count'] == 0
    with Store(db).connect() as conn:
        assert Store.rows(conn, 'ppt_pairings')[0]['status'] == 'revoked'
        assert len(Store.rows(conn, 'approvals')) == 40
