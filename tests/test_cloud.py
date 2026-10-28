import asyncio
from dataclasses import replace
import json
import os
from pathlib import Path
import re
import time
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from uuid import uuid4

import httpx
import jwt
import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from app.auth import AuthSettings
from app.main import create_app
from app.onelake import LakeFiles, OneLakeStore
from app.sessions import SharedSessions
from app.store import ROOT, Store
from usb_functions.api import create_business_api, reference_day
from usb_functions.lake_queue import LakeQueue
from usb_functions.lake_worker import LakeWorker
from usb_functions.remote_auth import EntraAPI

TENANT='22182a1f-8011-58a2-8ea1-2bab249da25a'
WEB='10000000-0000-0000-0000-000000000001'
API='10000000-0000-0000-0000-000000000002'
OID='10000000-0000-0000-0000-000000000003'
SIGNING='test-notebook-command-signing-key-at-least-48-characters-0123456789'
USER={'source':'entra','tenant_id':TENANT,'oid':OID,'roles':['USB.Operator'],'username':'cloud.test@example.invalid','name':'클라우드검증'}
PRIVATE=rsa.generate_private_key(public_exponent=65537,key_size=2048)


def access(**changes):
    now=time.time()
    payload={'iss':f'https://login.microsoftonline.com/{TENANT}/v2.0','aud':API,'tid':TENANT,
             'azp':WEB,'oid':OID,'ver':'2.0','scp':'USB.Access','roles':['USB.Operator'],
             'preferred_username':USER['username'],'exp':now+3600,'iat':now,'nbf':now-1}
    return jwt.encode(payload|changes,PRIVATE,algorithm='RS256',headers={'kid':'test-key'})


def validator():
    return EntraAPI(TENANT,API,WEB,key_client=SimpleNamespace(
        get_signing_key_from_jwt=lambda token:SimpleNamespace(key=PRIVATE.public_key())))


@pytest.fixture
def azure(monkeypatch):
    for key,value in {'USB_RUNTIME_MODE':'azure','ENTRA_TENANT_ID':TENANT,
                      'USB_FUNCTION_AUDIENCE':API,'USB_WEB_CLIENT_ID':WEB,
                      'USB_FUNCTION_URL':'https://function.example.invalid',
                      'USB_SESSION_ENCRYPTION_KEY':Fernet.generate_key().decode()}.items():
        monkeypatch.setenv(key,value)
    monkeypatch.delenv('USB_CLOUD_SAMPLE_WRITES',raising=False)


@pytest.fixture
def files():
    if os.getenv('USB_TEST_AZURITE')!='1':
        pytest.skip('Set USB_TEST_AZURITE=1 with local Azurite for storage integration tests')
    from azure.storage.blob import BlobServiceClient
    # Public emulator key comes from the installed local emulator, never a tenant credential.
    constants=Path(os.getenv('USB_TEST_AZURITE_CONSTANTS',str(ROOT/'.tools/node_modules/azurite/dist/src/common/utils/constants.js')))
    text=constants.read_text()
    key=re.search(r'EMULATOR_ACCOUNT_KEY = Buffer.from\("([^"\r\n]+)"',text).group(1)
    client=BlobServiceClient('http://127.0.0.1:10000/devstoreaccount1',credential={
        'account_name':'devstoreaccount1','account_key':key},api_version='2023-11-03')
    container=client.create_container('usb-cloud-test-'+uuid4().hex)
    try:
        yield LakeFiles(container,'sample-lakehouse/Files/usb-test')
    finally:
        container.delete_container()


@pytest.mark.parametrize('change',[{'aud':WEB},{'tid':WEB},{'azp':API},{'iss':'https://untrusted.invalid'},
                                  {'exp':0},{'nbf':time.time()+3600},{'scp':'User.Read'},
                                  {'roles':[]},{'ver':'1.0'},{'idtyp':'app'}])
def test_remote_tokens_reject_wrong_boundaries(change):
    with pytest.raises((jwt.PyJWTError,ValueError,PermissionError)):
        validator().validate(access(**change))


def test_remote_token_signature_and_role_mapping():
    assert validator().validate(access())['roles']==['USB.Operator']
    forged=jwt.encode({'aud':API},'test-forged-signature-secret-at-least-32chars',algorithm='HS256')
    with pytest.raises(jwt.PyJWTError):validator().validate(forged)


class FakeMSAL:
    def initiate_auth_code_flow(self,scopes,redirect_uri,response_mode):
        assert scopes==[f'api://{API}/USB.Access'] and redirect_uri.startswith('https://')
        return {'state':'test-state','auth_uri':f'https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/authorize',
                'code_verifier':'test-only-pkce-verifier-never-plaintext-in-store'}

    def acquire_token_by_auth_code_flow(self,flow,response):
        if response.get('state')!=flow['state'] or response.get('code')!='test-code':
            raise ValueError('Invalid login flow')
        return {'access_token':access(),'expires_in':3600,'id_token_claims':{
            'tid':TENANT,'aud':WEB,'iss':f'https://login.microsoftonline.com/{TENANT}/v2.0',
            'oid':OID,'roles':['USB.Operator'],'exp':time.time()+3600,'preferred_username':USER['username']}}


def settings():
    return AuthSettings('entra',TENANT,WEB,'test-cloud-web-credential',
                        'https://web.example.invalid/auth/callback',True,f'api://{API}/USB.Access',('10.1.0.0/24',))


def test_https_shared_login_across_web_instances_and_logout(azure,tmp_path):
    store1=Store(tmp_path/'shared.sqlite3',seed=False)
    store2=Store(tmp_path/'shared.sqlite3',seed=False)
    app1=create_app(auth_settings=settings(),client_factory=FakeMSAL,shared_store=store1)
    app2=create_app(auth_settings=settings(),client_factory=FakeMSAL,shared_store=store2)
    a=TestClient(app1,base_url='https://web.example.invalid',follow_redirects=False)
    b=TestClient(app2,base_url='https://web.example.invalid',follow_redirects=False)
    login=a.get('/auth/login')
    assert login.status_code==303 and 'Secure' in login.headers['set-cookie']
    b.cookies.update(a.cookies)
    callback=b.get('/auth/callback',params={'state':'test-state','code':'test-code'})
    assert callback.status_code==303 and callback.headers['location']=='/'
    assert 'Secure' in callback.headers['set-cookie'] and 'HttpOnly' in callback.headers['set-cookie']
    a.cookies.update(b.cookies)
    assert a.get('/api/me').json()['authenticated']
    with store1.connect() as db:
        serialized=json.dumps(store1.rows(db,'auth_sessions'))
        assert 'api_access_token' not in serialized and USER['username'] not in serialized
    replay=TestClient(app2,base_url='https://web.example.invalid',follow_redirects=False)
    replay.cookies.update(b.cookies)
    assert replay.get('/auth/callback',params={'state':'test-state','code':'test-code'}).headers['location']!='/'
    assert b.get('/api/me').json()['authenticated']
    assert a.post('/auth/logout',headers={'Origin':'https://bad.invalid','X-Local-Demo':'1'}).status_code==403
    assert a.post('/auth/logout',headers={'Origin':'https://web.example.invalid','X-Local-Demo':'1'}).status_code==200
    assert not b.get('/api/me').json()['authenticated']
    insecure=TestClient(app1,base_url='http://web.example.invalid')
    assert insecure.get('/auth/login',headers={'X-Forwarded-Proto':'https'}).status_code==400


def test_onelake_state_persists_rolls_back_and_sessions_are_single_use(files):
    a=OneLakeStore(files,'auth');b=OneLakeStore(files,'auth')
    key=Fernet.generate_key().decode();sa=SharedSessions(a,key);sb=SharedSessions(b,key)
    sa.put('flows','test-handle',{'flow':{'verifier':'private-test-verifier'},'expires':time.time()+600})
    assert 'private-test-verifier' not in files.read('state/auth.json').decode()
    assert sb.get('flows','test-handle',consume=True)['flow']['verifier']=='private-test-verifier'
    assert sa.get('flows','test-handle',consume=True) is None
    with pytest.raises(RuntimeError):
        with a.connect() as db:
            a.save(db,'test','rollback',{'x':1})
            raise RuntimeError('test rollback')
    with b.connect() as db:assert b.get(db,'test','rollback') is None
    with a.connect() as outer:
        a.save(outer,'test','keep',{'value':1})
        with pytest.raises(ValueError):
            with a.connect() as inner:
                a.save(inner,'test','partial',{'value':2})
                raise ValueError('nested business failure')
        assert a.get(outer,'test','partial') is None
    with b.connect() as db:assert b.get(db,'test','keep')=={'value':1}


def registration():
    today=reference_day().isoformat()
    return {'user_display_name':'노트북 검증','user_upn':'sample.user001@example.invalid','department':'검증',
            'usb_serial':'SAMPLE-CLOUD-NOTEBOOK-001','usb_name':'파일 검증 USB','permission':'read_only',
            'valid_from_date':today,'valid_until_date':today,'bitlocker_state':'encrypted',
            'approval_document_no':'SAMPLE-NOTEBOOK-001','request_reason':'비동기 처리 검증'}


def test_gateway_queues_notebook_applies_once_and_repairs_receipt(azure,files):
    store=OneLakeStore(files)
    queue=LakeQueue(files,SIGNING)
    api=create_business_api(tenant_id=TENANT,store=store,remote_auth=validator(),command_queue=queue)
    client=TestClient(api)
    assert client.get('/api/state',headers={'X-MS-CLIENT-PRINCIPAL-NAME':'admin'}).status_code==401
    assert client.post('/api/approvals',json=registration(),headers={'Authorization':'Bearer '+access(roles=['USB.Reader']),
                                                                  'Idempotency-Key':'test-1'}).status_code==403
    headers={'Authorization':'Bearer '+access(),'Idempotency-Key':'test-1'}
    response=client.post('/api/approvals',json=registration(),headers=headers)
    assert response.status_code==202
    request_id=response.json()['request_id']
    assert client.post('/api/approvals',json=registration(),headers=headers).json()['request_id']==request_id
    with store.connect() as db:assert store.rows(db,'approvals')==[]
    worker=LakeWorker(OneLakeStore(files),queue)
    result=asyncio.run(worker.run())
    assert result['processed']==1 and result['outcomes'][0]['status']=='completed'
    with store.connect() as db:assert len(store.rows(db,'approvals'))==1
    assert client.get('/api/cloud-requests/'+request_id,headers=headers).json()['status']=='completed'
    files.blob('results/'+request_id+'.json').delete_blob()
    assert asyncio.run(worker.run())['processed']==1
    with store.connect() as db:assert len(store.rows(db,'approvals'))==1
    assert asyncio.run(worker.run())['processed']==0
    bad=client.post('/api/approvals',json=registration()|{'usb_name':'changed'},headers=headers)
    assert bad.status_code==409


def test_gateway_to_function_forwards_real_api_token_only(azure,files,tmp_path):
    queue=LakeQueue(files,SIGNING)
    backend=create_business_api(tenant_id=TENANT,store=OneLakeStore(files),remote_auth=validator(),command_queue=queue)
    web=create_app(auth_settings=settings(),client_factory=FakeMSAL,shared_store=Store(tmp_path/'sessions.sqlite3',seed=False),
                   function_transport=httpx.ASGITransport(app=backend))
    client=TestClient(web,base_url='https://web.example.invalid',follow_redirects=False)
    client.get('/auth/login');client.get('/auth/callback',params={'state':'test-state','code':'test-code'})
    result=client.post('/api/approvals',json=registration(),headers={'Origin':'https://web.example.invalid','X-Local-Demo':'1'})
    assert result.status_code==202 and result.json()['accepted']
    assert client.get('/api/cloud-requests').json()['requests'][0]['status']=='queued'


def test_tampered_file_is_rejected_without_ledger_changes(azure,files):
    queue=LakeQueue(files,SIGNING);store=OneLakeStore(files)
    item=queue.enqueue('/api/approvals',registration(),USER,'tamper-test')
    name='requests/'+item['request_id']+'.json';body=json.loads(files.read(name));body['body']['usb_serial']='REAL-USB-1'
    files.blob(name).upload_blob(json.dumps(body).encode(),overwrite=True)
    assert asyncio.run(LakeWorker(store,queue).run())['outcomes'][0]['status']=='rejected'
    with store.connect() as db:assert not store.rows(db,'approvals')


def test_two_instances_serialize_updates_and_consume_login_flow_once(files):
    a,b=OneLakeStore(files,'auth'),OneLakeStore(files,'auth')
    def update(store):
        with store.connect() as db:
            old=store.get(db,'test','counter') or {'value':0}
            time.sleep(.03)
            store.save(db,'test','counter',{'value':old['value']+1})
    with ThreadPoolExecutor(max_workers=2) as pool:list(pool.map(update,[a,b]*4))
    with a.connect() as db:assert a.get(db,'test','counter')['value']==8
    key=Fernet.generate_key().decode()
    sessions=[SharedSessions(s,key) for s in (a,b)]
    sessions[0].put('flows','consume-once',{'flow':{},'expires':time.time()+60})
    with ThreadPoolExecutor(max_workers=2) as pool:
        results=list(pool.map(lambda s:s.get('flows','consume-once',consume=True),sessions))
    assert sum(result is not None for result in results)==1


def test_notebook_cells_are_valid_offline_and_keep_session_tokens_out_of_delta():
    import ast
    notebook=json.loads((ROOT/'notebooks/usb_lakehouse_worker.ipynb').read_text(encoding='utf-8'))
    for cell in notebook['cells']:
        if cell['cell_type']=='code':
            compile(''.join(cell['source']),'<fabric-cell>','exec',flags=ast.PyCF_ALLOW_TOP_LEVEL_AWAIT)
    source=(ROOT/'notebooks/usb_lakehouse_worker.py').read_text(encoding='utf-8')
    assert '"auth_sessions"' not in source and '"auth_flows"' not in source


def test_cloud_configuration_requires_https_and_explicit_auth(azure,monkeypatch):
    monkeypatch.setenv('USB_AUTH_MODE','demo')
    with pytest.raises(ValueError,match='Demo'):AuthSettings.from_env()
    monkeypatch.setenv('USB_AUTH_MODE','entra')
    monkeypatch.setenv('ENTRA_CLIENT_ID',WEB)
    monkeypatch.setenv('ENTRA_CLIENT_SECRET','test-client-secret-placeholder')
    monkeypatch.setenv('ENTRA_REDIRECT_URI','http://web.example.invalid/auth/callback')
    with pytest.raises(ValueError,match='HTTPS'):AuthSettings.from_env()
    monkeypatch.setenv('ENTRA_REDIRECT_URI','https://web.example.invalid/auth/callback')
    monkeypatch.setenv('USB_FUNCTION_SCOPE',f'api://{API}/USB.Access')
    monkeypatch.setenv('USB_TRUSTED_PROXY_CIDRS','0.0.0.0/0')
    with pytest.raises(ValueError,match='every proxy'):AuthSettings.from_env()


def test_cloud_mode_never_enables_sample_writes_from_local_env(azure):
    from app.runtime import write_flag
    assert write_flag('USB_PAIR_POLICY_WRITES','.env.pair-policy') is False
