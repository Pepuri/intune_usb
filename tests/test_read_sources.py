import copy
import json
from datetime import datetime, timezone
from types import SimpleNamespace

import httpx
import pytest
from fastapi.testclient import TestClient
from usb_functions.api import LookupInput, create_business_api
from usb_functions.bridge import sign_request
from usb_functions.read_sources import ReadSources, SourceError, decide

TENANT = '22182a1f-8011-58a2-8ea1-2bab249da25a'
UID = '0750b220-300d-55f7-95bd-3bab86e52cbb'
AAD = '44104811-7094-5088-89e8-c62e0a93e23b'
CLOCK = datetime(2026,10,28,6,tzinfo=timezone.utc)
KEY = 'read-lookup-test-key-with-at-least-forty-eight-characters'
USER = {'source':'entra','username':'operator@example.invalid','oid':UID,'tenant_id':TENANT,'roles':['USB.Operator']}


def request(**overrides):
    return LookupInput(**({'user_upn':'operator@example.invalid','usb_serial':'USB-REAL-1','permission':'read_only',
                          'valid_from_date':'2026-10-28','valid_until_date':'2026-11-01'} | overrides))


def facts():
    return {k:{'status':'ok','data':v} for k,v in {
      'entra':{'id':UID,'userPrincipalName':'operator@example.invalid','accountEnabled':True,'onPremisesSecurityIdentifier':'S-1-5-21-1-2-3-1000'},
      'defender':{'observations':[{'AadDeviceId':AAD,'VID':'1234','PID':'4321','InstancePath':'USB\\VID_1234&PID_4321\\USB-REAL-1'}]},
      'intune':{'value':[{'id':'managed-1','azureADDeviceId':AAD,'userId':'another-user','operatingSystem':'Windows','lastSyncDateTime':'2026-10-28T05:00:00Z'}]},
      'fabric':{'approvals':[{'approval_id':'REAL-1','is_sample':False,'user_object_id':UID,'user_upn':'operator@example.invalid',
         'usb_serial':'USB-REAL-1','approval_status':'active','validation_status':'verified','permission':'read_only',
         'approval_document_no':'GW-1','valid_from_date':'2026-10-01','valid_until_date':'2026-11-30'}],
         'pcs':[{'is_sample':False,'device_id':'managed-1','exception_assignment':'allowed'}]}}.items()}


def check(sources=None, body=None):
    return decide(body or request(), sources or facts(), clock=CLOCK)


def test_ready_requires_all_real_sources_and_never_applies_policy():
    r=check()
    assert r['decision']=='ready_for_review'
    assert r['eligible_pc_ids']==['managed-1']  # Another user's normal PC is valid.
    assert not r['policy_changed'] and not r['device_application_verified']


@pytest.mark.parametrize('source',['entra','defender','intune','fabric'])
def test_permissions_never_look_like_empty_success(source):
    s=facts();s[source]={'status':'permission_denied','http_status':403}
    assert check(s)['decision']=='pending'
    reasons=check(s)['pending_reasons']
    if source=='defender':assert 'usb_not_observed_in_last_30_days' not in reasons
    if source=='fabric':assert 'fabric_no_matching_real_valid_approval' not in reasons
    if source in ('fabric','entra'):assert check(s)['eligible_approval_count'] is None
    if source in ('fabric','defender','intune'):assert check(s)['eligible_pc_count'] is None


@pytest.mark.parametrize('field,value', [('is_sample',True),('user_object_id','wrong'),('usb_serial','other'),
    ('user_upn','other@company.com'),('approval_status','revoked'),('approval_status','expired'),
    ('approval_document_no',''),('valid_until_date','2026-10-27')])
def test_fabric_wrong_pair_or_invalid_approval_never_authorizes(field,value):
    s=facts();s['fabric']['data']['approvals'][0][field]=value
    assert check(s)['decision']=='pending'


def test_disabled_account_blocks_even_with_valid_ledger():
    s=facts();s['entra']['data']['accountEnabled']=False
    assert check(s)['decision']=='blocked'


def test_cloud_user_object_id_is_supported_without_a_windows_sid():
    s=facts();s['entra']['data']['onPremisesSecurityIdentifier']=None
    result=check(s)
    assert result['decision']=='ready_for_review'
    assert result['policy_identity_reference']['value']==UID
    assert result['policy_identity_reference']['kind']=='entra_object_id'
    assert result['policy_identity_reference']['endpoint_evaluation_verified'] is False


def test_absent_observation_is_pending_not_invalid_usb():
    s=facts();s['defender']['data']['observations']=[]
    assert 'usb_not_observed_in_last_30_days' in check(s)['pending_reasons']
    assert check(s)['decision']=='pending'


def test_events_without_serial_fields_are_not_reported_as_no_usb_activity():
    s=facts();s['defender']['data']={'observations':[],'coverage':{'event_count':5771,'serial_field_event_count':0}}
    reasons=check(s)['pending_reasons']
    assert 'usb_serial_telemetry_unavailable' in reasons
    assert 'usb_not_observed_in_last_30_days' not in reasons


def test_pnp_hid_parent_identity_does_not_verify_storage():
    s=facts();s['defender']['data']['observations'][0].update(ActionType='PnpDeviceConnected',ClassName='HIDClass')
    assert 'usb_storage_class_unconfirmed' in check(s)['pending_reasons']


def test_multiple_usb_candidates_and_incomplete_identity_require_review():
    s=facts();s['defender']['data']['observations'].append({'VID':'FFFF','PID':'0001','InstancePath':'other'})
    assert 'usb_multiple_candidates' in check(s)['pending_reasons']
    s=facts();s['defender']['data']['observations'][0]['VID']=''
    assert 'usb_identity_incomplete' in check(s)['pending_reasons']


def test_pc_encryption_and_input_do_not_establish_usb_bitlocker():
    s=facts();s['intune']['data']['value'][0]['isEncrypted']=True
    assert 'usb_bitlocker_evidence_required' in check(s,request(permission='read_write'))['pending_reasons']


@pytest.mark.parametrize('field,value',[('exception_assignment','excluded'),('exception_assignment','unclassified'),('is_sample',True),('device_id','wrong')])
def test_shared_unknown_sample_or_unmatched_pc_is_excluded(field,value):
    s=facts();s['fabric']['data']['pcs'][0][field]=value
    assert check(s)['eligible_pc_ids']==[] and check(s)['decision']=='pending'


def test_stale_pc_sync_and_truncated_results_block_readiness():
    s=facts();s['intune']['data']['value'][0]['lastSyncDateTime']='2026-10-01T00:00:00Z'
    assert check(s)['decision']=='pending'
    s=facts();s['intune']['data']['@odata.nextLink']='https://graph.microsoft.com/more'
    assert check(s)['decision']=='pending'


def test_overlapping_approvals_not_silently_selected():
    s=facts();s['fabric']['data']['approvals']*=2
    assert 'fabric_overlapping_approvals' in check(s)['pending_reasons']


def test_uses_current_kst_date_not_fixed_demo_date():
    assert check(body=request(valid_from_date='2026-10-01',valid_until_date='2026-10-27'))['decision']=='blocked'


class Tokens:
    def token(self, resource):return 'private-token'


def test_client_allowlist_rejects_writes_and_cross_host_without_sending_token():
    seen=[]
    reader=ReadSources(TENANT,tokens=Tokens(),transport=httpx.MockTransport(lambda r:seen.append(r)))
    for method,url in [('PATCH','https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/1'),
                       ('POST','https://graph.microsoft.com/v1.0/groups'),
                       ('GET','https://evil.example/v1.0/users/1'),
                       ('GET','https://graph.microsoft.com.evil.example/v1.0/users/1')]:
        with pytest.raises(SourceError):reader.request(method,url)
    assert seen==[]


def test_kql_literal_escaping_and_usb_serial_not_pc_serial():
    seen=[]
    def respond(req):
        seen.append(req)
        return httpx.Response(200,json={'results':[]} if req.method=='POST' else {'value':[]})
    reader=ReadSources(TENANT,tokens=Tokens(),transport=httpx.MockTransport(respond))
    reader.usb('x" | take 1 //')
    kql=json.loads(seen[0].content)['Query']
    assert 'SerialNumber =~ "x\\" | take 1 //"' in kql
    reader.devices(UID,[{'AadDeviceId':AAD}])
    assert AAD in seen[1].url.params['$filter'] and UID not in seen[1].url.params['$filter']
    assert 'serialNumber' not in seen[1].url.params['$select']
    reader.devices(UID)
    assert seen[2].url.path=='/v1.0/users/'+UID+'/managedDevices'
    assert '$filter' not in seen[2].url.params


def test_authenticated_endpoint_audits_without_mutating_ledger_or_policy(tmp_path):
    reader=SimpleNamespace(evaluate=lambda body:check(body=body))
    app=create_business_api(tmp_path/'read.sqlite',KEY,TENANT,read_sources=reader)
    with TestClient(app) as client:
        payload=request().model_dump_json().encode()
        assert client.post('/api/lookups/evaluate',content=payload).status_code==401
        with app.state.store.connect() as db:
            before=app.state.store.rows(db,'approvals')
        def submit(user):
            assertion=sign_request(KEY,user,'POST','/api/lookups/evaluate',payload)
            return client.post('/api/lookups/evaluate',content=payload,headers={'x-usb-assertion':assertion,'content-type':'application/json'})
        assert submit(USER|{'roles':['USB.Reader']}).status_code==403
        response=submit(USER)
        assert response.status_code==200 and response.json()['decision']=='ready_for_review'
        with app.state.store.connect() as db:
            assert app.state.store.rows(db,'approvals')==before
            assert db.execute('SELECT COUNT(*) FROM jobs').fetchone()[0]==0
            receipt=app.state.store.rows(db,'read_lookups')[0]
            assert receipt['actor_upn']=='operator@example.invalid'
            assert 'private-token' not in json.dumps(receipt)


def test_fabric_sql_uses_bound_parameters_and_closes_connection(monkeypatch):
    import mssql_python
    cfg=json.loads(__import__('pathlib').Path('config/read-sources.json').read_text())
    cfg['fabric_server']='unit.datawarehouse.fabric.microsoft.com'
    seen=[]
    class Cursor:
        description=[('approval_id',)]
        def execute(self, sql, parameters):
            seen.append((sql,parameters))
        def fetchall(self):return []
    class Connection:
        closed=False
        def cursor(self):return Cursor()
        def close(self):self.closed=True
    conn=Connection()
    def connect(connection_string, **kwargs):
        assert 'TrustServerCertificate=no' in connection_string
        assert 'ApplicationIntent=ReadOnly' in connection_string
        assert kwargs['token_provider'].get_token('https://database.windows.net/.default').token=='private-token'
        return conn
    monkeypatch.setattr(mssql_python,'connect',connect)
    reader=ReadSources(TENANT,config=cfg,tokens=Tokens())
    result=reader.fabric("o'hare@company.com","x';DROP TABLE t;--")
    assert result['approvals']==[] and conn.closed
    assert all(sql.startswith('SELECT TOP') for sql,params in seen)
    assert "DROP TABLE" not in seen[0][0] and seen[0][1][1]=="X';DROP TABLE T;--"


def test_live_clients_report_403_and_401_without_returning_service_secrets():
    from usb_functions.read_sources import source_result
    reader=ReadSources(TENANT,tokens=Tokens(),transport=httpx.MockTransport(
        lambda req:httpx.Response(403,json={'error':{'message':'private-token'}})))
    result=source_result(lambda:reader.user('operator@example.invalid'))
    assert result=={'status':'permission_denied','code':'http_403','http_status':403}
    assert 'private-token' not in json.dumps(result)
