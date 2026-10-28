import base64
import copy
import io
import json
import zipfile
from datetime import date
import xml.etree.ElementTree as ET

import httpx
import pytest

from test_sample_directory import lab
from usb_functions.pair_policy import compile_policy, evaluate_xml, validate_manifest, package_bytes, PairPolicyError, POLICY_ID, POLICY_NAME
from usb_functions.pair_service import PairPolicyService, CONFIG_PATH
from usb_functions.sample_directory import TENANT, PCS
from app.store import ROOT
from fastapi.testclient import TestClient
from usb_functions.api import create_business_api
from usb_functions.bridge import sign_request


def row(roster,index,serial,permission='read_only',key=None):
    return {'approval_id':key or f'PAIR-{index}-{serial}', 'is_sample':True,
            'user_upn':roster[index]['source_upn'],'usb_serial':serial,'permission':permission,
            'approval_status':'active','validation_status':'verified','bitlocker_state':'encrypted',
            'valid_from_date':'2026-10-01','valid_until_date':'2026-10-29'}


def test_many_to_many_pairs_have_no_cartesian_cross_grants(lab):
    s,d=lab;roster=s.config['users'];users=[r['object_id'] for r in roster]
    rows=[row(roster,0,'SAMPLE-USB-1'),row(roster,0,'SAMPLE-USB-2','read_write'),
          row(roster,1,'SAMPLE-USB-2'),row(roster,2,'SAMPLE-USB-3','read_write')]
    m=compile_policy(rows,roster,date(2026,10,28));settings=m['policy_body']['omaSettings']
    assert m['pair_count']==4 and m['user_count']==3 and m['usb_count']==3
    assert evaluate_xml(settings,users[0],'SAMPLE-USB-1','read')
    assert evaluate_xml(settings,users[0],'SAMPLE-USB-2','write',True)
    assert not evaluate_xml(settings,users[0],'SAMPLE-USB-2','write',False)
    assert evaluate_xml(settings,users[1],'SAMPLE-USB-2','read')
    assert not evaluate_xml(settings,users[1],'SAMPLE-USB-2','write',True)
    assert not evaluate_xml(settings,users[1],'SAMPLE-USB-1','read')
    assert not evaluate_xml(settings,users[0],'SAMPLE-USB-3','read')
    assert not evaluate_xml(settings,users[3],'SAMPLE-USB-1','read')
    assert not evaluate_xml(settings,users[0],'SAMPLE-USB-2','execute',True)
    assert m['baseline_verified'] is False and m['default_deny_baseline_required']


def test_duplicates_legacy_read_and_stable_ids_do_not_expand_permissions(lab):
    s,d=lab;roster=s.config['users'];r=row(roster,0,'SAMPLE-USB-1','read')
    m=compile_policy([r,r|{'approval_id':'duplicate'}],roster,date(2026,10,28))
    assert m['pair_count']==1 and m['pairs'][0]['permission']=='read_only'
    extended=compile_policy([r|{'valid_until_date':'2026-11-02'}],roster,date(2026,10,28))
    assert {a['omaUri'] for a in m['policy_body']['omaSettings']}=={a['omaUri'] for a in extended['policy_body']['omaSettings']}
    assert m['version']!=extended['version']


def test_revoked_expired_unverified_and_plain_write_are_excluded(lab):
    s,d=lab;roster=s.config['users']
    rows=[row(roster,0,'SAMPLE-USB-1')|{'approval_status':'revoked'},
          row(roster,1,'SAMPLE-USB-2')|{'valid_until_date':'2026-10-27'},
          row(roster,2,'SAMPLE-USB-3')|{'validation_status':'not_observed'},
          row(roster,3,'SAMPLE-USB-4','read_write')|{'bitlocker_state':'unknown'}]
    m=compile_policy(rows,roster,date(2026,10,28))
    assert not m['pairs'] and m['setting_count']==0 and len(m['excluded'])==4


@pytest.mark.parametrize('override',[{'user_upn':'outside@example.invalid'}, {'usb_serial':'REAL-USB-1'}, {'is_sample':False}])
def test_unknown_identity_or_real_usb_is_blocked(lab,override):
    s,d=lab
    with pytest.raises(PairPolicyError):compile_policy([row(s.config['users'],0,'SAMPLE-USB-1')|override],s.config['users'],date(2026,10,28))


def test_tampered_xml_unscoped_user_and_encryption_bypass_fail_matrix(lab):
    s,d=lab;roster=s.config['users']
    m=compile_policy([row(roster,0,'SAMPLE-USB-1','read_write')],roster,date(2026,10,28))
    bad=copy.deepcopy(m)
    encrypted=next(a for a in bad['policy_body']['omaSettings'] if 'encrypted media' in a['displayName'])
    node=ET.fromstring(base64.b64decode(encrypted['value']))
    desc=node.find('DescriptorIdList');desc.remove(desc.find('DeviceEncryptionStateId'))
    encrypted['value']=base64.b64encode(ET.tostring(node)).decode()
    with pytest.raises(PairPolicyError):validate_manifest(bad)
    bad=copy.deepcopy(m)
    rule=next(a for a in bad['policy_body']['omaSettings'] if a['displayName'].endswith(' read'))
    node=ET.fromstring(base64.b64decode(rule['value']))
    node.find('Entry/AccessMask').text='63'
    rule['value']=base64.b64encode(ET.tostring(node)).decode()
    with pytest.raises(PairPolicyError):validate_manifest(bad)


def test_zip_has_one_profile_and_xml_value_matches_oma_id(lab):
    s,d=lab;m=compile_policy([row(s.config['users'],0,'SAMPLE-USB-1')],s.config['users'],date(2026,10,28))
    with zipfile.ZipFile(io.BytesIO(package_bytes(m))) as z:
        patch=json.loads(z.read('policy-patch.json'))
        assert len(patch['omaSettings'])==2
        for a in patch['omaSettings']:
            assert z.read('xml/'+a['fileName'])==base64.b64decode(a['value'])


@pytest.fixture
def publisher(lab):
    directory,data=lab
    state={'policy':{'id':POLICY_ID,'displayName':POLICY_NAME,'@odata.type':'#microsoft.graph.windows10CustomConfiguration',
                   'omaSettings':json.loads((ROOT/'config/sample-policy/manifest.json').read_text())['policy_body']['omaSettings']},
           'assignments':[{'target':{'@odata.type':'#microsoft.graph.groupAssignmentTarget','groupId':PCS}}],
           'calls':[],'mismatch':False}
    def handle(request):
        path=request.url.path.removeprefix('/v1.0');state['calls'].append((request.method,path))
        if request.method=='GET' and path==CONFIG_PATH+'/assignments':return httpx.Response(200,json={'value':state['assignments']})
        if request.method=='GET' and path==CONFIG_PATH:return httpx.Response(200,json=state['policy'])
        if request.method=='PATCH' and path==CONFIG_PATH:
            body=json.loads(request.content)
            assert set(body)=={'@odata.type','description','omaSettings'}
            if not state['mismatch']:state['policy'].update(body)
            return httpx.Response(200,json=state['policy'])
        raise AssertionError((request.method,path))
    service=PairPolicyService(directory.store,TENANT,directory=directory,transport=httpx.MockTransport(handle),enabled=True,today=lambda:date(2026,10,28))
    return service,state,data


def test_single_policy_publish_readback_and_removed_pair_cleans_old_settings(publisher):
    service,cloud,data=publisher
    m=service.prepare();assert m['pair_count']==24
    assert service.publish(m['version'],'operator')['status']=='verified'
    assert len([c for c in cloud['calls'] if c[0]=='PATCH'])==1
    with service.store.connect() as db:
        old=service.store.get(db,'approvals','SAMPLE-APR-001');old['approval_status']='revoked';service.store.save(db,'approvals',old['approval_id'],old)
    new=service.prepare()
    assert new['pair_count']==23
    assert service.publish(new['version'],'operator')['status']=='verified'
    assert service.canonical(cloud['policy']['omaSettings'])==service.canonical(new['policy_body']['omaSettings'])
    assert all(path==CONFIG_PATH for method,path in cloud['calls'] if method=='PATCH')


@pytest.mark.parametrize('blocker',['disabled','device','assignment','unknown_setting','enabled_user','licensed'])
def test_publish_guards_refuse_broader_effects(publisher,blocker):
    service,cloud,data=publisher;m=service.prepare()
    if blocker=='disabled':service._enabled=False
    elif blocker=='device':data['pc_members']={'real-device'}
    elif blocker=='assignment':cloud['assignments']=[{'target':{'@odata.type':'#microsoft.graph.allDevicesAssignmentTarget'}}]
    elif blocker=='unknown_setting':cloud['policy']['omaSettings'].append({'omaUri':'unknown-setting','value':'a'})
    else:data[blocker]=True
    with pytest.raises(PairPolicyError):service.publish(m['version'],'operator')
    assert not any(method=='PATCH' for method,path in cloud['calls'])


def test_stale_plan_and_readback_failure_never_report_success(publisher):
    service,cloud,data=publisher;m=service.prepare()
    with pytest.raises(PairPolicyError):service.publish('0'*64,'operator')
    assert cloud['calls']==[]
    cloud['mismatch']=True
    with pytest.raises(PairPolicyError):service.publish(m['version'],'operator')
    with service.store.connect() as db:
        assert service.store.get(db,'pair_policy','published') is None
        assert service.store.rows(db,'pair_policy_events')[0]['status']=='unverified'
        assert service.store.rows(db,'pair_policy_backup')


def test_cache_and_disabled_timer_only_generate_local_snapshot(publisher):
    service,cloud,data=publisher;service._enabled=False
    m=service.prepare()
    assert service.prepare()['version']==m['version']
    assert service.tick()['status']=='candidate_ready'
    assert cloud['calls']==[]


def test_pair_api_requires_sso_operator_and_export_is_authenticated(publisher):
    service,cloud,data=publisher
    secret='local-pair-api-test-key-with-more-than-48-characters-abcdefghijklmnop'
    api=create_business_api(service.store.path,secret,TENANT,allow_demo=True,
                            sample_directory=service.directory,pair_policy_service=service)
    client=TestClient(api)
    user={'source':'entra','tenant_id':TENANT,'oid':'operator','username':'test@example.invalid','roles':['USB.Operator']}
    def request(method,path,body=None,identity=user):
        raw=json.dumps(body).encode() if body is not None else b''
        return client.request(method,path,content=raw,headers={'Content-Type':'application/json',
            'x-usb-assertion':sign_request(secret,identity,method,path,raw)})
    assert client.get('/api/pair-policy/package.zip').status_code==401
    assert request('GET','/api/pair-policy',identity=user|{'source':'demo'}).status_code==403
    preview=request('GET','/api/pair-policy').json()
    assert preview['pair_count']==24
    assert request('GET','/api/pair-policy/package.zip',identity=user|{'roles':['USB.Reader']}).status_code==200
    assert request('POST','/api/pair-policy/publish',{'version':preview['version']},user|{'roles':['USB.Reader']}).status_code==403
    assert request('POST','/api/pair-policy/publish',{'version':preview['version'],'policy_id':'other'}).status_code==422
    assert not any(method=='PATCH' for method,path in cloud['calls'])


@pytest.mark.parametrize('invalid',[None,'missing_reference','invalid_xml'])
def test_encrypted_xml_readback_uses_plaintext_and_fails_closed(publisher,invalid):
    service,cloud,data=publisher
    setting=service.prepare()['policy_body']['omaSettings'][0]
    metadata=dict(setting,value='PGEvPg==',isEncrypted=True,secretReferenceValueId='test/ref')
    if invalid=='missing_reference':metadata.pop('secretReferenceValueId')
    def handle(request):
        assert request.method=='GET'
        if request.url.path.startswith('/beta/'):
            return httpx.Response(200,json={'id':POLICY_ID,'omaSettings':[metadata]})
        if 'getOmaSettingPlainTextValue' in request.url.path:
            xml='<broken' if invalid=='invalid_xml' else base64.b64decode(setting['value']).decode()
            return httpx.Response(200,json={'value':xml})
        return httpx.Response(200,json={'id':POLICY_ID,'omaSettings':[dict(setting,value='PGEvPg==')]})
    service.transport=httpx.MockTransport(handle)
    if invalid:
        with pytest.raises(PairPolicyError):service.read_policy()
    else:
        actual=service.read_policy()['omaSettings']
        assert service.canonical(actual)==service.canonical([setting])
        assert 'secretReferenceValueId' not in actual[0]


def test_xml_comparison_ignores_service_whitespace():
    def item(xml):return {'omaUri':'uri','value':base64.b64encode(xml.encode()).decode()}
    assert PairPolicyService.canonical([item('<a><b>value</b></a>')])==PairPolicyService.canonical([item('<a>\n <b>value</b>\n</a>')])
