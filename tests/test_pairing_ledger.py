"""Existing authenticated registration/ledger endpoints feed USB/MTP XML; no tenant I/O."""
import json
import uuid
from datetime import date

import httpx
import pytest
from fastapi.testclient import TestClient
from usb_functions import api as api_module
from usb_functions.api import create_business_api
from usb_functions.bridge import sign_request
from usb_functions.pairing_preview import evaluate


U1, U2 = str(uuid.UUID(int=1)), str(uuid.UUID(int=2))


@pytest.fixture
def flow(tmp_path, monkeypatch):
    monkeypatch.setattr(api_module, 'DEMO_DATE', date(2026, 11, 8))
    monkeypatch.setenv('USB_PAIR_POLICY_WRITES', '1')  # New routes must refuse even with unsafe flags.
    def forbidden(*args, **kwargs):
        raise AssertionError('No remote transport is permitted during this flow')
    monkeypatch.setattr(httpx.HTTPTransport, 'handle_request', forbidden)
    key = 'local-ledger-bridge-' * 4
    app = create_business_api(db_path=tmp_path/'ledger.sqlite3', bridge_key=key, allow_demo=True)
    client = TestClient(app)
    user = {'source':'demo', 'username':'local@example.invalid', 'roles':['USB.Operator']}
    def call(method, path, data=None, roles=None, operation=None):
        body = json.dumps(data).encode() if data is not None else b''
        who = user if roles is None else user | {'roles': roles}
        headers = {'content-type':'application/json', 'x-usb-assertion':sign_request(key,who,method,path,body)}
        if operation: headers['idempotency-key'] = operation
        return client.request(method,path,content=body,headers=headers)
    return app, call, monkeypatch


def registration(user=U1, family='usb', identifier='SAMPLE-USB-A', upn='one@example.invalid'):
    return dict(user_display_name='가상 사용자',user_upn=upn,department='로컬 검증',
        user_object_id=user,policy_mode='usb_mtp_pairing',device_type=family,
        usb_serial=identifier,usb_name='가상 장치',permission='pairing_full',
        valid_from_date='2026-11-08',valid_until_date='2026-11-10',
        approval_document_no='LOCAL-TEST-001',request_reason='USB MTP 전체 흐름 검증')


def update(call, row, action, **extra):
    return call('POST',f"/api/approvals/{row['approval_id']}/{action}",
                dict(revision=row['revision'],reason='로컬 전체 흐름 검증',**extra))


def test_register_verify_extend_revoke_expire_and_negative_crosses(flow):
    app, call, patch = flow
    with app.state.store.connect() as db:
        original = app.state.store.rows(db,'approvals')
    rows = []
    for data in [registration(),registration(family='mtp',identifier=r'USB\VID_1234&PID_5678\TEST'),
                 registration(U2,identifier='SAMPLE-USB-B',upn='two@example.invalid')]:
        response = call('POST','/api/approvals',data)
        assert response.status_code == 201, response.text
        rows.append(response.json())
    assert call('GET','/api/pairing-policy').json()['pair_count'] == 0
    verified = [update(call,r,'verify').json() for r in rows]
    assert all(r['deployment_status']=='local_preview_ready' for r in verified)
    m = call('GET','/api/pairing-policy').json()
    assert m['ledger_source']=='approvals' and m['pair_count']==3 and m['matrix_checks']==105
    assert len(m['ledger'])==3 and m['policy_count']==m['assignment_group_count']==1
    settings=m['policy_body']['omaSettings']
    assert evaluate(settings,U1,'usb','SAMPLE-USB-A')
    assert evaluate(settings,U1,'mtp',rows[1]['usb_serial'])
    assert not evaluate(settings,U1,'usb','SAMPLE-USB-B')
    assert not evaluate(settings,U2,'mtp',rows[1]['usb_serial'])
    assert update(call,verified[0],'confirm_device').status_code==409
    extended=update(call,verified[0],'extend',valid_until_date='2026-11-15',approval_document_no='LOCAL-EXTEND').json()
    assert extended['revision']==3 and extended['valid_until_date']=='2026-11-15'
    assert update(call,verified[0],'revoke').status_code==409  # Stale revision cannot overwrite extension.
    assert update(call,verified[1],'revoke').json()['deployment_status']=='not_published'
    after_revoke=call('GET','/api/pairing-policy').json()
    assert after_revoke['pair_count']==2
    assert not evaluate(after_revoke['policy_body']['omaSettings'],U1,'mtp',rows[1]['usb_serial'])
    patch.setattr(api_module,'DEMO_DATE',date(2026,11,11))
    app.state.workflow.reference_date=date(2026,11,11)
    assert call('GET','/api/pairing-policy').json()['pair_count']==1  # Safe even before the expiry scan.
    assert call('POST','/api/expiry/scan',{}).status_code==200
    state=call('GET','/api/state').json()
    ended=next(r for r in state['approvals'] if r['approval_id']==verified[2]['approval_id'])
    assert ended['approval_status']=='expired' and ended['deployment_status']=='not_published'
    expired_preview=call('GET','/api/pairing-policy').json()
    assert any(x['id']==ended['approval_id'] and x['reason']=='expired' for x in expired_preview['excluded'])
    assert not evaluate(expired_preview['policy_body']['omaSettings'],U2,'usb','SAMPLE-USB-B')
    assert update(call,ended,'verify').status_code==409
    assert update(call,extended,'revoke').status_code==200
    assert call('GET','/api/pairing-policy').json()['pair_count']==0
    assert call('GET','/api/pairing-policy/package.zip').status_code==200
    assert call('POST','/api/pairing-policy/publish',{}).status_code==403
    plan=call('GET','/api/deployment/preview').json()
    assert not any(r['approval_id'] in plan['pending']+plan['withdrawals'] for r in rows)
    with app.state.store.connect() as db:
        assert not app.state.store.rows(db,'ppt_pairings')  # No second copy of approval data.
        assert not app.state.store.rows(db,'sample_ledger_links')
        history=app.state.store.rows(db,'history')
        assert any(h['event_type']=='expired' and h['approval_id']==ended['approval_id'] for h in history)
        assert len(app.state.store.rows(db,'approvals'))==len(original)+3
        permissions={r['approval_id']:r['permission'] for r in app.state.store.rows(db,'approvals')}
        assert all(permissions[r['approval_id']]==r['permission'] for r in original)


def test_identity_device_validation_duplicates_idempotency_and_reader(flow):
    app, call, patch = flow
    data=registration()
    first=call('POST','/api/approvals',data,operation='same-request')
    assert first.status_code==201
    assert call('POST','/api/approvals',data,operation='same-request').json()['approval_id']==first.json()['approval_id']
    assert call('POST','/api/approvals',data|{'usb_name':'changed'},operation='same-request').status_code==409
    assert call('POST','/api/approvals',data|{'user_upn':'alias@example.invalid'}).status_code==409
    for changes in [{'device_type':'mtp','usb_serial':'not-a-full-path'}, {'user_object_id':str(uuid.UUID(int=0))},
                    {'user_object_id':None},{'usb_serial':'ANY*'},{'permission':'read_only'},
                    {'sample_group_key':'SAMPLE-APR-001'}]:
        assert call('POST','/api/approvals',data|changes).status_code==422
    assert call('POST','/api/approvals',registration(U2),roles=['USB.Reader']).status_code==403
    assert call('GET','/api/pairing-policy',roles=['USB.Reader']).status_code==200
    assert 'device_type' in call('GET','/api/export.csv').text


def test_real_rehearsal_user_is_allowlisted_and_resolved_before_save(flow, monkeypatch):
    from types import SimpleNamespace
    import usb_functions.read_sources as sources
    app,call,_=flow
    upn='pilot@tenant.test'
    body=registration(upn=upn)
    assert call('POST','/api/approvals',body).status_code==422
    monkeypatch.setenv('USB_REHEARSAL_USER_UPN',upn)
    monkeypatch.setattr(sources,'ReadSources',lambda tenant:SimpleNamespace(user=lambda value:{
        'id':U1,'accountEnabled':True,'userPrincipalName':upn}))
    assert call('POST','/api/approvals',body|{'user_object_id':U2}).status_code==409
    saved=call('POST','/api/approvals',body)
    assert saved.status_code==201,saved.text
    assert saved.json()['identity_source']=='graph_user_verified_device_assumed'
    assert saved.json()['validation_status']=='not_observed'
    assert call('POST','/api/approvals',body|{'user_upn':'other@tenant.test'}).status_code==422
