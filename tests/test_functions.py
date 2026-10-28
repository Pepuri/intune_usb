import json
import time
from datetime import date
from concurrent.futures import ThreadPoolExecutor

import jwt
import pytest
from fastapi.testclient import TestClient
from app.main import create_app
from usb_functions.api import create_business_api
from usb_functions.bridge import sign_request

KEY='a-local-test-bridge-key-with-more-than-forty-eight-characters-1234'
TENANT='22182a1f-8011-58a2-8ea1-2bab249da25a'
USER={'source':'entra','username':'operator@example.invalid','oid':'test-object','tenant_id':TENANT,'roles':['USB.Operator']}
HEADERS={'X-Local-Demo':'1'}


@pytest.fixture
def client(tmp_path):
    with TestClient(create_app(tmp_path/'queue.sqlite3')) as c:yield c


def post(c,path,body=None,extra=None):
    return c.post(path,json=body or {},headers=HEADERS|(extra or {}))


def register(c, serial='SAMPLE-FUNCTION-001', until='2026-11-28', extra=None):
    return post(c,'/api/approvals',dict(user_display_name='함수검증',user_upn='function.test@example.invalid',department='검증팀',
                usb_serial=serial,usb_name='가상 Function USB',approval_document_no='SAMPLE-FUNCTION-APPROVAL',
                request_reason='Function 전체 흐름 검증',permission='read_write',valid_from_date='2026-10-28',
                valid_until_date=until,bitlocker_state='encrypted'),extra)


def verified(c, serial='SAMPLE-FUNCTION-001', until='2026-11-28'):
    row=register(c,serial,until).json()
    return post(c,f"/api/approvals/{row['approval_id']}/verify",{'revision':row['revision'],'reason':'모의 식별 증거 확인'}).json()


def enqueue(c, failures=0):
    plan=c.get('/api/deployment/preview').json()
    response=post(c,'/api/deployment/simulate',{'fingerprint':plan['fingerprint'],'simulate_failures':failures})
    assert response.status_code==202
    return response.json()['job']


def row(c,key):
    return next(r for r in c.get('/api/state').json()['approvals'] if r['approval_id']==key)


def make_ready(c,job):
    with c.app.state.store.connect() as db:
        db.execute('UPDATE jobs SET available=0 WHERE id=?',(job['id'],))


def test_registration_idempotency_key_is_atomic_and_actor_scoped(client):
    first=register(client,extra={'Idempotency-Key':'once-001'})
    second=register(client,extra={'Idempotency-Key':'once-001'})
    assert first.status_code==second.status_code==201 and first.json()==second.json()
    assert len(client.get('/api/state').json()['approvals'])==41
    assert register(client,'SAMPLE-FUNCTION-002',extra={'Idempotency-Key':'once-001'}).status_code==409


def test_queue_acceptance_deduplication_receipt_and_pair_integrity(client):
    new=verified(client)
    job=enqueue(client)
    duplicate=enqueue(client)
    assert job['id']==duplicate['id'] and len(client.get('/api/jobs').json()['jobs'])==1
    assert row(client,new['approval_id'])['deployment_status']=='publish_pending'
    result=post(client,'/api/worker/drain').json()
    assert result['outcomes']==[{'job_id':job['id'],'status':'succeeded'}]
    state=client.get('/api/jobs').json()
    snapshot=state['policy']
    assert snapshot['publisher']=='mock' and not snapshot['deployable_to_intune']
    assert snapshot['baseline_block_required'] and snapshot['bitlocker_write_required']
    assert len(snapshot['pairs'])==25 and len(snapshot['target_pcs'])==4
    by_id={r['approval_id']:r for r in client.get('/api/state').json()['approvals']}
    assert all((p['user_object_id'],p['usb_serial'])==(by_id[p['approval_id']]['user_object_id'],by_id[p['approval_id']]['usb_serial']) for p in snapshot['pairs'])
    before=client.get('/api/state').json()
    assert post(client,'/api/worker/drain').json()['outcomes']==[]
    assert client.get('/api/state').json()['history']==before['history']
    assert client.app.state.backend.state.workflow.claim(job['id']) is None
    assert row(client,new['approval_id'])['deployment_status']=='published'
    assert client.get('/api/jobs').json()['jobs'][0]['attempt_history'][0]['source']=='manual-api'


def test_concurrent_queue_accepts_one_job(client):
    plan=client.get('/api/deployment/preview').json()
    with ThreadPoolExecutor(max_workers=2) as pool:
        jobs=list(pool.map(lambda _:post(client,'/api/deployment/simulate',{'fingerprint':plan['fingerprint']}).json()['job']['id'],range(2)))
    assert jobs[0]==jobs[1] and len(client.get('/api/jobs').json()['jobs'])==1


def test_queued_snapshot_cannot_overwrite_newer_ledger(client):
    new=verified(client)
    job=enqueue(client)
    assert post(client,f"/api/approvals/{new['approval_id']}/revoke",{'revision':new['revision'],'reason':'게시 전 승인 취소'}).status_code==200
    assert post(client,'/api/worker/drain').json()['outcomes'][0]['status']=='superseded'
    assert all(p['approval_id']!=new['approval_id'] for p in client.get('/api/jobs').json()['policy']['pairs'])
    assert client.get('/api/jobs').json()['jobs'][0]['id']==job['id']


def test_transient_failure_backoff_then_success(client):
    new=verified(client)
    job=enqueue(client,2)
    for attempt in (1,2):
        outcome=post(client,'/api/worker/drain').json()['outcomes'][0]
        assert outcome['status']=='retry_wait'
        recorded=client.get('/api/jobs').json()['jobs'][0]
        assert recorded['attempts']==attempt and recorded['available']>time.time()
        assert row(client,new['approval_id'])['deployment_status']=='publish_pending'
        assert post(client,'/api/worker/drain').json()['outcomes']==[]
        make_ready(client,job)
    assert post(client,'/api/worker/drain').json()['outcomes'][0]['status']=='succeeded'
    assert client.get('/api/jobs').json()['jobs'][0]['attempts']==3


def test_dead_letter_explicit_retry_and_no_false_device_confirmation(client):
    new=verified(client)
    job=enqueue(client,5)
    for _ in range(3):
        post(client,'/api/worker/drain')
        make_ready(client,job)
    assert client.get('/api/jobs').json()['jobs'][0]['status']=='dead_letter'
    assert row(client,new['approval_id'])['deployment_status']=='publish_failed'
    assert post(client,f"/api/jobs/{job['id']}/retry").status_code==200
    assert post(client,'/api/worker/drain').json()['outcomes'][0]['status']=='succeeded'
    assert row(client,new['approval_id'])['deployment_status']=='published'
    assert not client.get('/api/jobs').json()['jobs'][0]['result']['device_confirmed']
    attempts=client.get('/api/jobs').json()['jobs'][0]['attempt_history']
    assert len(attempts)==4 and any(a['status']=='dead_letter' for a in attempts)


def test_worker_lease_fences_old_owner_and_recovers_after_crash(client):
    job=enqueue(client)
    engine=client.app.state.backend.state.workflow
    first=engine.claim(job['id'])
    with client.app.state.store.connect() as db:db.execute('UPDATE jobs SET lease_until=0 WHERE id=?',(job['id'],))
    second=engine.claim(job['id'])
    assert second['attempts']==2 and first['lease_token']!=second['lease_token']
    assert engine.execute(first)=='lease_lost'
    assert engine.execute(second)=='succeeded'
    assert engine.execute(second)=='lease_lost'


def test_queue_survives_restart(client):
    job=enqueue(client)
    from app.store import Store
    from usb_functions.workflow import Workflow
    reloaded=Workflow(Store(client.app.state.store.path),date(2026,10,28))
    assert reloaded.drain()['outcomes'][0]['job_id']==job['id']
    assert reloaded.jobs()[0]['status']=='succeeded'


def test_expiry_is_idempotent_and_does_not_publish_pending_new_allowances(client):
    new=verified(client,until='2026-10-28')
    enqueue(client);post(client,'/api/worker/drain')
    pending=verified(client,'SAMPLE-FUNCTION-UNPUBLISHED')
    engine=client.app.state.backend.state.workflow
    engine.reference_date=date(2026,10,29)
    first=engine.expire();second=engine.expire()
    assert first['job_id']==second['job_id'] and new['approval_id'] in first['withdrawals']
    expired=row(client,new['approval_id'])
    assert expired['approval_status']=='expired' and expired['deployment_status']=='withdrawal_pending'
    assert engine.drain()['outcomes'][0]['status']=='succeeded'
    pairs=client.get('/api/jobs').json()['policy']['pairs']
    assert new['approval_id'] not in [p['approval_id'] for p in pairs]
    assert pending['approval_id'] not in [p['approval_id'] for p in pairs]
    assert row(client,new['approval_id'])['deployment_status']=='withdrawal_published'


def signed(c, method, target, body=b'',user=None,token=None):
    return c.request(method,target,content=body,headers={'X-USB-Assertion':token or sign_request(KEY,user or USER,method,target,body),'Content-Type':'application/json'})


def test_function_boundary_rejects_unsigned_spoofed_wrong_tenant_and_body(tmp_path):
    api=create_business_api(tmp_path/'boundary.sqlite3',KEY,TENANT)
    with TestClient(api) as c:
        assert c.get('/api/state',headers={'X-MS-CLIENT-PRINCIPAL-NAME':'admin'}).status_code==401
        assert signed(c,'GET','/api/state').status_code==200
        assert signed(c,'GET','/api/state',user=USER|{'tenant_id':'wrong'}).status_code==401
        assert signed(c,'GET','/api/state',user=USER|{'source':'demo'}).status_code==401
        token=sign_request(KEY,USER,'POST','/api/worker/drain',b'{}')
        assert signed(c,'POST','/api/worker/drain',b'{"tampered":true}',token=token).status_code==401
        assert signed(c,'POST','/api/worker/drain',b'{}',token=token).status_code==200
        assert signed(c,'POST','/api/worker/drain',b'{}',token=token).status_code==409
        reader=USER|{'roles':['USB.Reader']}
        assert signed(c,'GET','/api/jobs',user=reader).status_code==200
        assert signed(c,'POST','/api/worker/drain',b'{}',user=reader).status_code==403
        expired=jwt.encode({'iss':'usb-local-ui','aud':'usb-local-functions','iat':0,'exp':1,'jti':'test','method':'GET','target':'/api/state','body_sha256':'none','user':USER},KEY,algorithm='HS256')
        assert signed(c,'GET','/api/state',token=expired).status_code==401


def test_function_boundary_denies_url_substitution(tmp_path):
    api=create_business_api(tmp_path/'query.sqlite3',KEY,TENANT)
    with TestClient(api) as c:
        token=sign_request(KEY,USER,'GET','/api/export.csv?ids=SAMPLE-APR-001',b'')
        assert signed(c,'GET','/api/export.csv?ids=SAMPLE-APR-002',token=token).status_code==401


def test_expiry_reconciles_withdrawal_after_superseded_message(client):
    new=verified(client,until='2026-10-28')
    enqueue(client);post(client,'/api/worker/drain')
    engine=client.app.state.backend.state.workflow
    engine.reference_date=date(2026,10,29)
    first=engine.expire()
    assert register(client,'SAMPLE-FUNCTION-NEWER').status_code==201
    assert engine.drain()['outcomes'][0]['status']=='superseded'
    second=engine.expire()
    assert second['job_id']!=first['job_id']
    assert engine.drain()['outcomes'][0]['status']=='succeeded'
    assert row(client,new['approval_id'])['deployment_status']=='withdrawal_published'
