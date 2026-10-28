import time
from urllib.parse import urlparse, parse_qs

import pytest
from fastapi.testclient import TestClient
from app.auth import AuthSettings, ROLE_OPERATOR, ROLE_READER
from app.main import create_app

TENANT='22182a1f-8011-58a2-8ea1-2bab249da25a'
CLIENT='10000000-0000-0000-0000-000000000001'
SETTINGS=AuthSettings('entra',TENANT,CLIENT,'test-only-not-a-credential')
HEADERS={'X-Local-Demo':'1'}


class FakeMSAL:
    def __init__(self, claims):
        self.claims=claims
    def initiate_auth_code_flow(self, scopes, redirect_uri, response_mode):
        assert scopes==[] and response_mode=='query'
        return {'auth_uri':'https://login.microsoftonline.com/'+TENANT+'/oauth2/v2.0/authorize?state=state-1', 'state':'state-1','nonce':'nonce-1'}
    def acquire_token_by_auth_code_flow(self, flow, response):
        if response.get('state') != flow['state'] or response.get('code')!='test-code':
            raise ValueError('Fake state validation')
        return {'id_token_claims':self.claims,'access_token':'never-store-this-token'}


def claims(**changes):
    return dict(tid=TENANT,aud=CLIENT,iss=f'https://login.microsoftonline.com/{TENANT}/v2.0',
                oid='operator-object-id',name='테스트 운영자',preferred_username='test.operator@example.invalid',
                roles=[ROLE_OPERATOR],exp=time.time()+3600)|changes


def client_for(tmp_path, identity=None):
    fake=FakeMSAL(identity or claims())
    app=create_app(tmp_path/'auth.sqlite3',auth_settings=SETTINGS,client_factory=lambda:fake)
    return TestClient(app,base_url='http://localhost:8765',follow_redirects=False)


def login(c, state='state-1'):
    assert c.get('/auth/login').status_code==303
    return c.get('/auth/callback',params={'state':state,'code':'test-code'})


def test_anonymous_protected_and_headers_cannot_impersonate(tmp_path):
    with client_for(tmp_path) as c:
        assert c.get('/').status_code==200 and 'login.js' in c.get('/').text
        assert c.get('/api/state').status_code==401
        assert c.get('/api/export.csv').status_code==401
        assert c.get('/api/state',headers={'X-MS-CLIENT-PRINCIPAL-NAME':'admin@example.com'}).status_code==401
        assert not c.get('/api/me').json()['authenticated']


def test_operator_login_actor_logout_and_token_isolation(tmp_path):
    with client_for(tmp_path) as c:
        response=login(c)
        assert response.status_code==303 and response.headers['location']=='/'
        assert 'httponly' in response.headers['set-cookie'].lower()
        assert 'never-store' not in response.headers['set-cookie']
        assert c.get('/api/me').json()['can_write']
        row=c.get('/api/state').json()['approvals'][0]
        result=c.post(f"/api/approvals/{row['approval_id']}/revoke",json={'revision':row['revision'],'reason':'인증 사용자 기록 검증'},headers=HEADERS)
        assert result.status_code==200
        history=c.get('/api/state').json()['history']
        assert history[0]['actor_upn']=='test.operator@example.invalid'
        result=c.post('/auth/logout',headers=HEADERS)
        assert result.status_code==200 and TENANT in result.json()['logout_url']
        assert c.get('/api/state').status_code==401


def test_reader_can_read_but_not_write(tmp_path):
    with client_for(tmp_path,claims(roles=[ROLE_READER])) as c:
        login(c)
        assert c.get('/api/state').status_code==200
        assert not c.get('/api/me').json()['can_write']
        assert c.post('/api/deployment/simulate',json={'fingerprint':'any'},headers=HEADERS).status_code==403
        assert c.post('/api/approvals',json={},headers=HEADERS).status_code==403
        assert c.post('/api/pcs/any',json={},headers=HEADERS).status_code==403


@pytest.mark.parametrize('changes',[{'tid':'wrong-tenant'},{'aud':'wrong-client'}, {'iss':'https://untrusted.example'},
                                   {'exp':0},{'roles':[]},{'roles':['Unrelated.Admin']}])
def test_invalid_claims_and_missing_roles_fail_closed(tmp_path,changes):
    with client_for(tmp_path,claims(**changes)) as c:
        result=login(c)
        assert 'auth_error=' in result.headers['location']
        assert not c.get('/api/me').json()['authenticated']
        assert c.get('/api/state').status_code==401


def test_state_replay_missing_flow_and_session_expiry(tmp_path):
    with client_for(tmp_path) as c:
        assert 'invalid_flow' in c.get('/auth/callback?code=test-code&state=state-1').headers['location']
        assert 'invalid_identity' in login(c,'wrong-state').headers['location']
        login(c)
        assert c.get('/api/state').status_code==200
        assert 'invalid_flow' in c.get('/auth/callback?code=test-code&state=state-1').headers['location']
        login(c)
        for value in c.app.state.auth.sessions.values():
            value['expires']=0
        assert c.get('/api/state').status_code==401


def test_config_pending_never_falls_back_to_demo(tmp_path):
    config=AuthSettings('entra',TENANT)
    with TestClient(create_app(tmp_path/'pending.sqlite3',auth_settings=config),follow_redirects=False) as c:
        assert not c.get('/auth/status').json()['configured']
        assert c.get('/api/state').status_code==401
        assert 'configuration_pending' in c.get('/auth/login').headers['location']


def test_demo_identity_explicitly_marked(tmp_path):
    with TestClient(create_app(tmp_path/'demo.sqlite3',auth_settings=AuthSettings())) as c:
        assert c.get('/api/me').json()['user']['source']=='demo'
