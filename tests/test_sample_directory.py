import copy
import json
from datetime import date
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from app.store import Store, ROOT
from usb_functions.sample_directory import SampleDirectory, LabError, TENANT, USERS, PCS, GRAPH
from usb_functions.api import create_business_api
from usb_functions.bridge import sign_request


class Tokens:
    def token(self, resource):
        assert resource == 'https://graph.microsoft.com'
        return 'test-token'


@pytest.fixture
def lab(tmp_path):
    cfg=json.loads((ROOT/'config/sample-tenant-resources.json').read_text(encoding='utf-8-sig'))
    # Fake server state only: these tests never call a tenant.
    data={'members':{cfg['users'][0]['object_id']},'pc_members':set(),'calls':[], 'write_fail':False,
          'licensed':False,'enabled_user':False,'foreign':False,'defer_read':False}
    def handle(request):
        path=request.url.path.removeprefix('/v1.0')
        data['calls'].append((request.method,path))
        if path in (f'/groups/{USERS}',f'/groups/{PCS}'):
            is_user=path.endswith(USERS)
            return httpx.Response(200,json={'id':USERS if is_user else PCS,
                'displayName':cfg['user_group' if is_user else 'device_group']['name'],
                'description':'USB_SAMPLE_FLOW_20261028','securityEnabled':True,'mailEnabled':False,
                'groupTypes':[],'isAssignableToRole':False})
        if path.endswith('/members'):
            members=data['members'] if USERS in path else data['pc_members']
            if data['foreign'] and USERS in path: members=members|{'foreign-user'}
            return httpx.Response(200,json={'value':[{'id':m} for m in members]})
        if path.startswith('/users/'):
            row=next(r for r in cfg['users'] if r['object_id']==path.split('/')[-1])
            index=cfg['users'].index(row)+1
            return httpx.Response(200,json={'id':row['object_id'],'userPrincipalName':row['upn'],
                'accountEnabled':data['enabled_user'],'assignedLicenses':[{'skuId':'a'}] if data['licensed'] else [],
                'employeeId':f'USBS261028-{index:03d}'})
        if request.method=='POST':
            if data['write_fail']:return httpx.Response(503)
            obj=json.loads(request.content)['@odata.id'].split('/')[-1]
            data['members'].add(obj)
            return httpx.Response(204)
        if request.method=='DELETE':
            assert path.endswith('/$ref')
            if data['write_fail']:return httpx.Response(503)
            data['members'].discard(path.split('/')[-2])
            return httpx.Response(204)
        raise AssertionError((request.method,path))
    store=Store(tmp_path/'lab.sqlite3')
    controller=SampleDirectory(store,TENANT,config=cfg,tokens=Tokens(),transport=httpx.MockTransport(handle),
                               enabled=True,today=lambda:date(2026,10,28))
    return controller,data


def test_remove_approve_revoke_real_adapter_routes_and_audit(lab):
    s,d=lab; key='SAMPLE-APR-001'
    before=s.store.path.read_bytes()
    for action,until,member in [('revoke',None,False),('approve',date(2026,10,29),True),('revoke',None,False)]:
        result=s.change(key,action,until,'샘플 흐름 검증','operator')
        assert result['status']=='verified' and result['after_member']==member
    assert len([c for c in d['calls'] if c[0]=='DELETE'])==2
    assert len([c for c in d['calls'] if c[0]=='POST'])==1
    assert all(c[1].startswith('/groups/'+USERS+'/members/') and c[1].endswith('/$ref')
               for c in d['calls'] if c[0]!='GET')
    state=s.status()
    assert len(state['history'])==3 and state['live']['device_member_count']==0
    assert state['users'][0]['sid_lookup']['mode']=='assumed'
    assert state['users'][0]['sid_lookup']['verified'] is False
    assert state['users'][0]['sid_lookup']['used_for_graph_or_policy'] is False
    with s.store.connect() as db:
        assert len(s.store.rows(db,'approvals'))==40
        assert len(s.store.rows(db,'history'))==len(json.loads((ROOT/'sample_data/sample_usb_history.json').read_text(encoding='utf-8-sig')))


@pytest.mark.parametrize('blocker',['pc_members','licensed','enabled_user','foreign'])
def test_refuses_devices_real_users_or_foreign_members(lab,blocker):
    s,d=lab
    d[blocker]={'actual-device'} if blocker=='pc_members' else True
    with pytest.raises(LabError):s.change('SAMPLE-APR-001','approve',date(2026,10,29),'실패 검증','operator')
    assert not any(method!='GET' for method,path in d['calls'])


def test_disabled_and_unknown_user_never_write(lab):
    s,d=lab;s._enabled=False
    with pytest.raises(LabError):s.change('SAMPLE-APR-001','revoke',None,'비활성 검증','operator')
    s._enabled=True
    with pytest.raises(LabError):s.change('LOCAL-OTHER','revoke',None,'대상 검증','operator')
    with pytest.raises(LabError):s.request('DELETE','/users/'+s.users['SAMPLE-APR-001']['object_id'])
    with pytest.raises(LabError):s.request('DELETE',f'/groups/{USERS}/members/'+s.users['SAMPLE-APR-001']['object_id'])
    with pytest.raises(LabError):s.request('POST',f'/groups/{PCS}/members/$ref',{})
    assert d['calls']==[]


def test_write_failure_is_audited_and_pending_revoke_reconciles(lab):
    s,d=lab;d['write_fail']=True
    with pytest.raises(LabError):s.change('SAMPLE-APR-001','revoke',None,'오류 재시도','operator')
    state=s.status()
    assert state['history'][0]['status']=='unverified'
    assert state['users'][0]['grant']['state']=='revoke_pending'
    d['write_fail']=False
    outcome=s.expire(source='manual-test')
    assert outcome['outcomes'][0]['status']=='verified'
    assert not d['members']


def test_expiry_and_idempotent_replay(lab):
    s,d=lab
    s.change('SAMPLE-APR-001','approve',date(2026,10,28),'오늘 승인','operator')
    # Already-member approval only updates the receipt/expiry, without duplicate Graph writes.
    assert not any(m=='POST' for m,p in d['calls'])
    assert s.expire()['outcomes']==[]
    s.today=lambda:date(2026,10,29)
    result=s.expire(source='scheduled-test')
    assert result['outcomes'][0]['after_member'] is False
    assert result['outcomes'][0]['source']=='scheduled-test'
    assert s.expire()['outcomes']==[]


def test_expiry_cannot_cancel_newer_approval(lab):
    s,d=lab
    s.change('SAMPLE-APR-001','approve',date(2026,11,1),'연장 승인','operator')
    assert s.change('SAMPLE-APR-001','expire',None,'오래된 작업','timer')['status']=='superseded'
    assert d['members']


def test_default_kst_clock_works_without_system_timezone_database(lab):
    s,d=lab
    runtime=SampleDirectory(s.store,TENANT,config=s.config,tokens=Tokens(),enabled=False)
    assert isinstance(runtime.today(), date)


def test_old_pending_revoke_cannot_remove_a_new_approval(lab):
    s,d=lab
    old=s.change('SAMPLE-APR-001','revoke',None,'초기 회수','operator')
    s.change('SAMPLE-APR-001','approve',date(2026,11,1),'새 승인','operator')
    result=s.change('SAMPLE-APR-001','revoke',None,'오래된 재시도','timer',expected_event=old['event_id'])
    assert result['status']=='superseded' and d['members']


def test_readback_waits_for_graph_replication(lab,monkeypatch):
    s,d=lab
    s.change('SAMPLE-APR-001','revoke',None,'초기 회수','operator')
    original=s.members
    reads={'n':0}
    def delayed(group):
        if group==USERS and d['members'] and reads['n']==0:
            reads['n']+=1
            return set()
        return original(group)
    monkeypatch.setattr(s,'members',delayed)
    monkeypatch.setattr('usb_functions.sample_directory.time.sleep',lambda seconds:None)
    assert s.change('SAMPLE-APR-001','approve',date(2026,11,1),'전파 지연','operator')['status']=='verified'


def test_api_requires_entra_operator_and_signed_bridge(lab):
    s,d=lab; secret='local-test-key-with-more-than-48-characters-abcdefghijklmnop'
    api=create_business_api(s.store.path,secret,TENANT,allow_demo=True,sample_directory=s)
    c=TestClient(api)
    path='/api/sample-directory/SAMPLE-APR-001'
    body=json.dumps({'action':'revoke','reason':'권한 경계 검증'}).encode()
    base={'source':'entra','username':'operator@example.invalid','oid':'operator-id','tenant_id':TENANT,'roles':['USB.Operator']}
    assert c.post(path,content=body).status_code==401
    for changes,expected in [({'roles':['USB.Reader']},403),({'source':'demo'},403),({},200)]:
        headers={'Content-Type':'application/json','x-usb-assertion':sign_request(secret,base|changes,'POST',path,body)}
        assert c.post(path,content=body,headers=headers).status_code==expected
