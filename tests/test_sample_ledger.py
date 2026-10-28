import json
from datetime import date

from fastapi.testclient import TestClient

from test_sample_directory import lab
from usb_functions.api import create_business_api
from usb_functions.bridge import sign_request
from usb_functions.sample_directory import TENANT
from usb_functions.sample_ledger import SampleLedger, SERIAL

KEY='local-test-key-with-more-than-48-characters-abcdefghijklmnop'
USER={'source':'entra','username':'operator@example.invalid','oid':'operator','tenant_id':TENANT,'roles':['USB.Operator']}


def client(lab):
    s,d=lab
    return TestClient(create_business_api(s.store.path,KEY,TENANT,allow_demo=True,sample_directory=s))


def post(c,path,body,user=USER):
    raw=json.dumps(body).encode()
    return c.post(path,content=raw,headers={'Content-Type':'application/json',
                  'x-usb-assertion':sign_request(KEY,user,'POST',path,raw)})


def body():
    return dict(user_display_name='진세아',user_upn='sample.user001@example.invalid',department='정보보안팀',
        usb_serial=SERIAL,usb_name='공통 샘플 USB',approval_document_no='SAMPLE-GROUP-LEDGER',
        request_reason='실제 샘플 그룹 연결 검증',permission='read_only',valid_from_date='2026-10-28',
        valid_until_date='2026-10-28',bitlocker_state='unknown',sample_group_key='SAMPLE-APR-001')


def test_registration_verify_extend_revoke_sync_and_history(lab):
    s,d=lab;c=client(lab)
    row=post(c,'/api/approvals',body()).json();key=row['approval_id']
    assert row['sample_group_key']=='SAMPLE-APR-001'
    assert not any(m!='GET' for m,p in d['calls'])
    sync=post(c,'/api/sample-directory/sync',{}).json()
    assert sync['outcomes'][0]['member'] is False  # pending verification cannot grant
    row=post(c,f'/api/approvals/{key}/verify',{'revision':row['revision'],'reason':'SID 완료 가정'}).json()
    assert post(c,'/api/sample-directory/sync',{}).json()['outcomes'][0]['member'] is True
    assert post(c,'/api/sample-directory/sync',{}).json()['outcomes']==[]
    with s.store.connect() as db:
        preview=c.app.state.workflow.preview(db)
        assert key not in [p['approval_id'] for p in preview['pairs']]
        assert key not in preview['pending']
    row=post(c,f'/api/approvals/{key}/extend',{'revision':row['revision'],'reason':'연장 검증',
        'valid_until_date':'2026-11-01','approval_document_no':'SAMPLE-EXT'}).json()
    assert post(c,'/api/sample-directory/sync',{}).json()['outcomes'][0]['member'] is True
    with s.store.connect() as db:
        assert s.store.get(db,'sample_grants','SAMPLE-APR-001')['valid_until_date']=='2026-11-01'
    assert post(c,f'/api/approvals/{key}/confirm_device',{'revision':row['revision'],'reason':'금지 검증'}).status_code==409
    assert post(c,'/api/sample-directory/SAMPLE-APR-001',{'action':'revoke','reason':'이중 제어 금지'}).status_code==409
    row=post(c,f'/api/approvals/{key}/revoke',{'revision':row['revision'],'reason':'원장 회수 검증'}).json()
    assert post(c,'/api/sample-directory/sync',{}).json()['outcomes'][0]['member'] is False
    assert not d['members']
    with s.store.connect() as db:
        assert key not in c.app.state.workflow.preview(db)['withdrawals']
        assert len([r for r in s.store.rows(db,'history') if r['event_type']=='sample_group_sync'])==4
        assert s.store.get(db,'approvals','SAMPLE-APR-001')['approval_status']=='active'


def test_binding_validation_and_demo_cannot_opt_in(lab):
    s,d=lab;c=client(lab)
    for override in ({'permission':'read_write'}, {'usb_serial':'SAMPLE-OTHER-USB'},
                     {'sample_group_key':'SAMPLE-APR-002'}, {'sample_group_key':'SAMPLE-APR-999'}):
        assert post(c,'/api/approvals',body()|override).status_code==409
    assert post(c,'/api/approvals',body(),USER|{'source':'demo'}).status_code==403
    assert post(c,'/api/approvals',body(),USER|{'roles':['USB.Reader']}).status_code==403
    with s.store.connect() as db:
        assert len(s.store.rows(db,'approvals'))==40
        assert s.store.rows(db,'sample_ledger_links')==[]


def test_failed_membership_retries_latest_revoke_instead_of_old_grant(lab):
    s,d=lab;c=client(lab)
    row=post(c,'/api/approvals',body()).json();key=row['approval_id']
    row=post(c,f'/api/approvals/{key}/verify',{'revision':row['revision'],'reason':'식별 가정'}).json()
    # Force absent then fail approval. The retry must use the latest ledger, not replay the old grant.
    d['members']=set();d['write_fail']=True
    assert post(c,'/api/sample-directory/sync',{}).json()['outcomes'][0]['state']=='retry_pending'
    post(c,f'/api/approvals/{key}/revoke',{'revision':row['revision'],'reason':'승인 취소'})
    d['write_fail']=False
    result=post(c,'/api/sample-directory/sync',{}).json()['outcomes'][0]
    assert result['state']=='verified' and result['member'] is False
    assert not d['members']


def test_date_start_and_expiry_use_kst_clock_and_never_touch_unlinked_accounts(lab):
    s,d=lab;c=client(lab)
    row=post(c,'/api/approvals',body()|{'valid_from_date':'2026-10-29','valid_until_date':'2026-10-30'}).json()
    post(c,f"/api/approvals/{row['approval_id']}/verify",{'revision':row['revision'],'reason':'가정 검증'})
    sync=SampleLedger(s.store,TENANT,directory=s)
    assert sync.drain()['outcomes'][0]['member'] is False
    s.today=lambda:date(2026,10,29)
    assert sync.drain()['outcomes'][0]['member'] is True
    s.today=lambda:date(2026,10,31)
    assert sync.drain()['outcomes'][0]['member'] is False
    with s.store.connect() as db:
        assert s.store.get(db,'approvals',row['approval_id'])['approval_status']=='expired'
    assert {p for m,p in d['calls'] if m=='DELETE'}=={f"/groups/29a01e82-62e5-55ad-a594-355fcc097923/members/{s.users['SAMPLE-APR-001']['object_id']}/$ref"}


def test_closed_and_withdrawn_binding_can_be_reused_without_replaying_old_row(lab):
    s,d=lab;c=client(lab)
    first=post(c,'/api/approvals',body()).json()
    assert post(c,'/api/approvals',body()|{'usb_serial':SERIAL,'valid_from_date':'2026-11-01','valid_until_date':'2026-11-02'}).status_code==409
    post(c,f"/api/approvals/{first['approval_id']}/revoke",{'revision':first['revision'],'reason':'종료 처리'})
    post(c,'/api/sample-directory/sync',{})
    second=post(c,'/api/approvals',body()).json()
    assert second['approval_id']!=first['approval_id']
    post(c,f"/api/approvals/{second['approval_id']}/verify",{'revision':second['revision'],'reason':'새 승인 검증'})
    post(c,'/api/sample-directory/sync',{})
    assert d['members']
    with s.store.connect() as db:
        assert s.store.get(db,'sample_ledger_links',first['approval_id'])['active'] is False
