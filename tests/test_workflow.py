import csv
import io
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient
from app.main import create_app

HEADERS = {'X-Local-Demo':'1'}


@pytest.fixture
def client(tmp_path):
    with TestClient(create_app(tmp_path/'test.sqlite3')) as c:
        yield c


def sample(**changes):
    return dict(user_display_name='김테스트',user_upn='test.new@example.invalid',department='검증팀',
                usb_serial='SAMPLE-TEST-001',usb_name='테스트 USB',approval_document_no='SAMPLE-GW-TEST-1',
                request_reason='로컬 처리 흐름 검증',permission='read_write',valid_from_date='2026-10-28',
                valid_until_date='2026-11-28',bitlocker_state='encrypted',**changes)


def post(c, path, body):
    return c.post(path,json=body,headers=HEADERS)


def change(c, row, action, **extra):
    return post(c,f"/api/approvals/{row['approval_id']}/{action}",
                dict(revision=row['revision'],reason='테스트 처리 근거',**extra))


def test_seed_counts_and_relations(client):
    s=client.get('/api/state').json()
    assert len(s['approvals'])==40 and len(s['pcs'])==8 and len(s['history'])==80
    assert all(r['is_sample'] for r in s['approvals'])
    assert {h['approval_id'] for h in s['history']} <= {r['approval_id'] for r in s['approvals']}
    assert client.get('/').status_code==200


def test_full_workflow_separates_publish_and_device(client):
    response=post(client,'/api/approvals',sample()); assert response.status_code==201
    row=response.json()
    assert row['approval_status']=='verification_pending'
    assert change(client,row,'confirm_device').status_code==409
    row=change(client,row,'verify').json()
    assert row['deployment_status']=='publish_pending'
    plan=client.get('/api/deployment/preview').json()
    assert row['approval_id'] in plan['pending']
    queued=post(client,'/api/deployment/simulate',{'fingerprint':plan['fingerprint']})
    assert queued.status_code==202 and queued.json()['job']['status']=='queued'
    assert change(client,row,'confirm_device').status_code==409
    assert post(client,'/api/worker/drain',{}).json()['outcomes'][0]['status']=='succeeded'
    row=next(r for r in client.get('/api/state').json()['approvals'] if r['approval_id']==row['approval_id'])
    assert row['deployment_status']=='published' and row['approval_status']=='deployment_pending'
    row=change(client,row,'confirm_device').json()
    assert row['deployment_status']=='device_applied' and row['approval_status']=='active'
    row=change(client,row,'extend',valid_until_date='2026-12-28',approval_document_no='SAMPLE-EXT-1').json()
    assert row['deployment_status']=='publish_pending'
    row=change(client,row,'revoke').json()
    assert row['deployment_status']=='withdrawal_pending'
    assert change(client,row,'confirm_device').status_code==409
    plan=client.get('/api/deployment/preview').json()
    assert row['approval_id'] not in [p['approval_id'] for p in plan['pairs']]
    post(client,'/api/deployment/simulate',{'fingerprint':plan['fingerprint']})
    post(client,'/api/worker/drain',{})
    row=next(r for r in client.get('/api/state').json()['approvals'] if r['approval_id']==row['approval_id'])
    assert row['deployment_status']=='withdrawal_published'
    row=change(client,row,'confirm_device').json()
    assert row['deployment_status']=='withdrawal_confirmed' and row['approval_status']=='revoked'
    events=[h for h in client.get('/api/state').json()['history'] if h['approval_id']==row['approval_id']]
    assert len(events)==8 and all('before' in h and 'after' in h for h in events)


def test_registration_guards(client):
    data=sample()
    assert post(client,'/api/approvals',data).status_code==201
    assert post(client,'/api/approvals',data).status_code==409
    for changes in [{'user_upn':'real@company.com'},{'usb_serial':'REAL-1234'},
                    {'valid_until_date':'2026-10-01'},{'request_reason':'   '},
                    {'valid_from_date':'2026-12-01'}]:
        assert post(client,'/api/approvals',data|changes).status_code==422


def test_unencrypted_write_and_future_period_not_deployed(client):
    row=post(client,'/api/approvals',sample()|{'bitlocker_state':'not_encrypted'}).json()
    assert change(client,row,'verify').status_code==409
    future=post(client,'/api/approvals',sample()|{'usb_serial':'SAMPLE-FUTURE-1','valid_from_date':'2026-11-01'}).json()
    assert change(client,future,'verify').status_code==200
    pairs=client.get('/api/deployment/preview').json()['pairs']
    assert future['approval_id'] not in [p['approval_id'] for p in pairs]


def test_stale_writes_and_preview_rejected(client):
    r=client.get('/api/state').json()['approvals'][0]
    old_plan=client.get('/api/deployment/preview').json()
    assert change(client,r,'extend',valid_until_date='2027-01-01',approval_document_no='SAMPLE-EXT').status_code==200
    assert change(client,r,'revoke').status_code==409
    assert post(client,'/api/deployment/simulate',{'fingerprint':old_plan['fingerprint']}).status_code==409


def test_concurrent_updates_only_one_wins(client):
    row=client.get('/api/state').json()['approvals'][0]
    with ThreadPoolExecutor(max_workers=2) as pool:
        statuses=list(pool.map(lambda _:change(client,row,'revoke').status_code,range(2)))
    assert sorted(statuses)==[200,409]


def test_pc_exclusion_keeps_block_and_pending_withdrawal(client):
    old_plan=client.get('/api/deployment/preview').json()
    pc=next(p for p in client.get('/api/state').json()['pcs'] if p['allow_policy_assignment']=='assigned')
    result=post(client,f"/api/pcs/{pc['device_id']}",dict(revision=pc['revision'],assignment='excluded',reason='공용 PC로 전환'))
    assert result.status_code==200
    pc=result.json()
    assert pc['baseline_block_required'] and pc['bitlocker_policy_required']
    assert pc['group_sync_status']=='pending' and pc['withdrawal_status']=='pending'
    assert pc['device_name'] not in client.get('/api/deployment/preview').json()['target_pcs']
    assert post(client,'/api/deployment/simulate',{'fingerprint':old_plan['fingerprint']}).status_code==409


def test_extension_cannot_overlap_another_approval(client):
    first=post(client,'/api/approvals',sample()).json()
    first=change(client,first,'verify').json()
    assert post(client,'/api/approvals',sample()|{'valid_from_date':'2026-12-01','valid_until_date':'2026-12-15'}).status_code==201
    assert change(client,first,'extend',valid_until_date='2026-12-10',approval_document_no='SAMPLE-EXT-2').status_code==409


def test_export_filter_and_formula_escape(client):
    row=post(client,'/api/approvals',sample()|{'user_display_name':'=1+1'}).json()
    res=client.get('/api/export.csv',params={'ids':row['approval_id']})
    rows=list(csv.DictReader(io.StringIO(res.text.lstrip('\ufeff'))))
    assert len(rows)==1 and rows[0]['user_display_name']=="'=1+1"
    assert rows[0]['demo_reference_date']=='2026-10-28' and rows[0]['exported_at_utc']


def test_local_only_headers_origin_and_persistence(tmp_path):
    db=tmp_path/'persist.sqlite3'
    with TestClient(create_app(db)) as client:
        assert client.post('/api/approvals',json=sample()).status_code==403
        assert client.post('/api/approvals',json=sample(),headers=HEADERS|{'Origin':'https://other.example'}).status_code==403
        assert client.get('/api/state',headers={'Host':'outside.example'}).status_code==400
        assert post(client,'/api/approvals',sample()).status_code==201
    with TestClient(create_app(db)) as client:
        assert len(client.get('/api/state').json()['approvals'])==41
