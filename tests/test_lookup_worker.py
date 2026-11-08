import asyncio
import json
import pytest

from app.store import Store
from usb_functions.lake_queue import LakeQueue
from usb_functions.lake_worker import LakeWorker


def test_cloud_pairing_registration_changes_and_expiry_never_publish(tmp_path, monkeypatch):
    monkeypatch.setenv('USB_PAIRING_PREVIEW_ENABLED','1')
    w, lookup_id, sources, user = worker(tmp_path,monkeypatch)
    def forbidden(*args,**kwargs): raise AssertionError('Policy/group publishers must not run')
    monkeypatch.setattr(w.api.state.workflow,'drain',forbidden)
    monkeypatch.setattr(w.api.state.workflow,'expire',forbidden)
    data={'policy_mode':'usb_mtp_pairing','permission':'pairing_full','device_type':'mtp',
          'user_object_id':'10000000-0000-0000-0000-000000000003','user_upn':'pair@example.invalid',
          'user_display_name':'Pair test','department':'Test','usb_serial':r'USB\VID_1234&PID_5678\MTP-TEST',
          'usb_name':'MTP test','valid_from_date':'2020-01-01','valid_until_date':'2099-12-01',
          'approval_document_no':'LOCAL-001','request_reason':'Cloud metadata preview test'}
    def process(path,body,key):
        rid=w.queue.enqueue(path,body,user,key)['request_id']
        asyncio.run(w.run_pending_intake())
        return json.loads(w.queue.files.read('results/'+rid+'.json'))
    registered=process('/api/approvals',data,'pair-register')
    assert registered['status']=='completed',registered
    row=registered['result']
    path='/api/approvals/'+row['approval_id']
    verified=process(path+'/verify',{'revision':1,'reason':'Assume identity resolved'},'pair-verify')
    assert verified['result']['deployment_status']=='local_preview_ready'
    extended=process(path+'/extend',{'revision':2,'reason':'Extend preview','valid_until_date':'2099-12-31',
                                  'approval_document_no':'LOCAL-EXT'},'pair-extend')
    assert extended['result']['valid_until_date']=='2099-12-31'
    revoked=process(path+'/revoke',{'revision':3,'reason':'Revoke preview'},'pair-revoke')
    assert revoked['result']['deployment_status']=='not_published'
    other=process('/api/approvals',data|{'usb_serial':r'USB\VID_1234&PID_5678\MTP-EXPIRE'},'pair-expire-register')['result']
    from datetime import date
    w.api.state.workflow.reference_date=date(2100,1,1)
    asyncio.run(w.run_pending_intake())
    with w.store.connect() as db:
        assert w.store.get(db,'approvals',other['approval_id'])['approval_status']=='expired'
        assert not w.store.rows(db,'sample_ledger_links')


class Files:
    def __init__(self): self.data = {}
    def read(self, name): return self.data.get(name)
    def names(self, prefix): return [name for name in self.data if name.startswith(prefix)]
    def create(self, name, raw):
        if name in self.data: return False
        self.data[name] = raw
        return True


def worker(tmp_path, monkeypatch):
    tenant = '10000000-0000-0000-0000-000000000099'
    for key, value in {'USB_RUNTIME_MODE': 'azure', 'ENTRA_TENANT_ID': tenant,
        'USB_FUNCTION_AUDIENCE': '10000000-0000-0000-0000-000000000001',
        'USB_WEB_CLIENT_ID': '10000000-0000-0000-0000-000000000002',
        'USB_CLOUD_SAMPLE_WRITES': '0', 'USB_PAIR_POLICY_WRITES': '0',
        'USB_PAIR_POLICY_AUTO_PUBLISH': '0', 'USB_SAMPLE_GROUP_WRITES': '0'}.items():
        monkeypatch.setenv(key, value)
    queue = LakeQueue(Files(), 'test-lookup-only-signing-key-at-least-forty-eight-characters')
    user = {'source': 'entra', 'tenant_id': tenant, 'oid': 'test-operator',
            'roles': ['USB.Operator'], 'username': 'operator@example.invalid'}
    class Sources:
        calls = 0
        def evaluate(self, body):
            self.calls += 1
            return {'decision': 'pending', 'sources': {}, 'policy_changed': False}
    sources = Sources()
    store = Store(tmp_path/'lookup.sqlite3', seed=False)
    item = queue.enqueue('/api/lookups/evaluate', {'user_upn': 'test@example.invalid',
        'usb_serial': 'SAMPLE-READ-ONLY', 'permission': 'read_only',
        'valid_from_date': '2026-10-29', 'valid_until_date': '2026-10-29'}, user, 'lookup')
    return LakeWorker(store, queue, read_sources=sources), item['request_id'], sources, user


def test_single_lookup_records_result_once_without_maintenance(tmp_path, monkeypatch):
    w, rid, sources, user = worker(tmp_path, monkeypatch)
    def forbidden(*args, **kwargs): raise AssertionError('Maintenance must not run')
    monkeypatch.setattr(w.api.state.workflow, 'expire', forbidden)
    monkeypatch.setattr(w.api.state.workflow, 'drain', forbidden)
    result = asyncio.run(w.run_lookup(rid))
    assert result['status'] == 'completed'
    assert result['source'] == 'manual-notebook-read-only'
    assert result['result']['decision'] == 'pending'
    assert asyncio.run(w.run_lookup(rid)) == result
    assert sources.calls == 1
    with w.store.connect() as db:
        assert not w.store.rows(db, 'approvals')
        assert not w.store.rows(db, 'history')
        assert len(w.store.rows(db, 'read_lookups')) == 1
    # Rebuilding a missing output file uses the durable receipt, without another lookup.
    del w.queue.files.data['results/' + rid + '.json']
    assert asyncio.run(w.run_lookup(rid)) == result
    assert sources.calls == 1


def test_lookup_mode_rejects_other_routes_and_enabled_write_flags(tmp_path, monkeypatch):
    w, rid, sources, user = worker(tmp_path, monkeypatch)
    other = w.queue.enqueue('/api/pair-policy/publish', {}, user, 'publish')['request_id']
    with pytest.raises(ValueError, match='Only a lookup'):
        asyncio.run(w.run_lookup(other))
    monkeypatch.setenv('USB_PAIR_POLICY_WRITES', '1')
    with pytest.raises(ValueError, match='every write flag'):
        asyncio.run(w.run_lookup(rid))
    assert sources.calls == 0


def test_pending_lookup_batch_skips_writes_and_completed_requests(tmp_path, monkeypatch):
    w, rid, sources, user = worker(tmp_path, monkeypatch)
    other = w.queue.enqueue('/api/pair-policy/publish', {}, user, 'publish')['request_id']
    result = asyncio.run(w.run_pending_lookups())
    assert result['processed'] == 1 and sources.calls == 1
    assert result['outcomes'][0]['source'] == 'notebook-read-only-batch'
    assert w.queue.files.read('results/' + other + '.json') is None
    assert asyncio.run(w.run_pending_lookups())['processed'] == 0
    assert sources.calls == 1


def test_pending_batch_rejects_tampered_lookup_without_query(tmp_path, monkeypatch):
    w, rid, sources, user = worker(tmp_path, monkeypatch)
    name = 'requests/' + rid + '.json'
    command = json.loads(w.queue.files.read(name))
    command['body']['usb_serial'] = 'TAMPERED'
    w.queue.files.data[name] = json.dumps(command).encode()
    result = asyncio.run(w.run_pending_lookups())
    assert result['processed'] == 1 and result['outcomes'][0]['status'] == 'rejected'
    assert sources.calls == 0


def test_metadata_intake_registers_once_without_policy_or_group_work(tmp_path, monkeypatch):
    from usb_functions.api import reference_day
    w, rid, sources, user = worker(tmp_path, monkeypatch)
    today = reference_day().isoformat()
    body = {'user_display_name': '자동 저장 검증', 'user_upn': 'intake@example.invalid',
            'department': '테스트', 'usb_serial': 'SAMPLE-INTAKE-ONLY', 'usb_name': '가상 USB',
            'permission': 'read_only', 'valid_from_date': today, 'valid_until_date': today,
            'approval_document_no': 'SAMPLE-INTAKE-TEST', 'request_reason': '원장 저장 검증',
            'bitlocker_state': 'unknown'}
    queued = w.queue.enqueue('/api/approvals', body, user, 'intake-register')['request_id']
    other = w.queue.enqueue('/api/pair-policy/publish', {}, user, 'intake-publish')['request_id']
    def forbidden(*args, **kwargs): raise AssertionError('Maintenance must not run')
    monkeypatch.setattr(w.api.state.workflow, 'expire', forbidden)
    monkeypatch.setattr(w.api.state.workflow, 'drain', forbidden)
    assert asyncio.run(w.run_pending_intake())['processed'] == 2
    receipt = json.loads(w.queue.files.read('results/' + queued + '.json'))
    assert receipt['status'] == 'completed'
    assert receipt['result']['approval_status'] == 'verification_pending'
    assert receipt['result']['deployment_status'] == 'not_published'
    assert w.queue.files.read('results/' + other + '.json') is None
    assert asyncio.run(w.run_pending_intake())['processed'] == 0
    with w.store.connect() as db:
        assert len(w.store.rows(db, 'approvals')) == 1
        assert len(w.store.rows(db, 'history')) == 1
        assert not w.store.rows(db, 'pair_policy_events')
        assert not w.store.rows(db, 'sample_group_history')
    # Group-linked intake is held back even though it is syntactically a registration.
    linked = w.queue.enqueue('/api/approvals', body | {'sample_group_key': 'SAMPLE-APR-001'},
                             user, 'intake-linked')['request_id']
    asyncio.run(w.run_pending_intake())
    assert json.loads(w.queue.files.read('results/' + linked + '.json'))['status'] == 'rejected'
