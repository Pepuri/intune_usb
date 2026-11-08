# %% [markdown]
# USB 접수·조회 요청 정기 처리 — Intune 변경 비활성
# Graph 읽기 전용 앱과 전용 Key Vault를 먼저 연결합니다.
# 일반 가상 승인 정보 저장과 조회 요청만 처리합니다. 만료 처리, 그룹 변경, 정책 게시는 실행하지 않습니다.

# %% parameters
KEY_VAULT_URI = ""
GRAPH_CLIENT_ID = ""
MAX_REQUESTS = 50
SOURCE_SHA256 = ""
APP_FOLDER = "usb-operations"

# %% [markdown]
# 필요한 패키지는 이 노트북에 연결된 Fabric Environment에서 관리합니다.
# 배치 실행에서는 인라인 패키지 설치를 사용하지 않습니다.

# %%
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import time
import zipfile
import notebookutils
from azure.core.credentials import AccessToken

if not KEY_VAULT_URI.startswith('https://') or not GRAPH_CLIENT_ID:
    raise ValueError('노트북 전용 읽기 앱과 Key Vault 연결이 필요합니다.')
if not re.fullmatch('[a-f0-9]{64}', SOURCE_SHA256):
    raise ValueError('감사한 소스 해시를 확인하세요.')
if APP_FOLDER != 'usb-operations':
    raise ValueError('이 노트북은 USB 앱 폴더만 사용합니다.')
ctx = notebookutils.runtime.context
base = Path('/lakehouse/default/Files') / APP_FOLDER
cfg = json.loads((base/'config/lookup-worker.json').read_text())
assert str(ctx['defaultLakehouseId']) == cfg['lakehouse_id']
assert str(ctx['defaultLakehouseWorkspaceId']) == cfg['workspace_id']
package_path = base/'code/lookup-worker.zip'
assert hashlib.sha256(package_path.read_bytes()).hexdigest() == SOURCE_SHA256
runtime = Path(tempfile.mkdtemp(prefix='usb-read-only-'))
with zipfile.ZipFile(package_path) as package:
    for entry in package.infolist():
        if not (runtime/entry.filename).resolve().is_relative_to(runtime.resolve()):
            raise ValueError('Unsafe package path')
    package.extractall(runtime)
sys.path.insert(0, str(runtime))
os.environ.update({
    'USB_RUNTIME_MODE': 'azure', 'ENTRA_TENANT_ID': cfg['tenant_id'],
    'USB_ONELAKE_WORKSPACE_ID': cfg['workspace_id'],
    'USB_ONELAKE_LAKEHOUSE_ID': cfg['lakehouse_id'], 'USB_ONELAKE_PREFIX': APP_FOLDER,
    'USB_SAMPLE_DIRECTORY_JSON': json.dumps(cfg['sample_directory']),
    'USB_READ_SOURCES_JSON': json.dumps(cfg['read_sources']),
    'USB_SOURCE_AUTH': 'client_secret', 'ENTRA_CLIENT_ID': GRAPH_CLIENT_ID,
    'ENTRA_CLIENT_SECRET': notebookutils.credentials.getSecret(KEY_VAULT_URI, 'usb-notebook-graph-secret'),
    'USB_REQUEST_SIGNING_KEY': notebookutils.credentials.getSecret(KEY_VAULT_URI, 'usb-request-signing-key'),
    'USB_CLOUD_SAMPLE_WRITES': '0', 'USB_PAIR_POLICY_WRITES': '0',
    'USB_PAIR_POLICY_AUTO_PUBLISH': '0', 'USB_SAMPLE_GROUP_WRITES': '0', 'USB_PAIRING_PREVIEW_ENABLED': '1',
})

class StorageCredential:
    def get_token(self, *scopes, **kwargs):
        assert all(s == 'https://storage.azure.com/.default' for s in scopes)
        return AccessToken(notebookutils.credentials.getToken('storage'), int(time.time())+300)

from app.onelake import LakeFiles, OneLakeStore
from usb_functions.lake_queue import LakeQueue, canonical
from usb_functions.lake_worker import LakeWorker
from usb_functions.read_sources import ReadSources, SourceError

files = LakeFiles.from_env(credential=StorageCredential())
store = OneLakeStore(files)
queue = LakeQueue(files, os.environ['USB_REQUEST_SIGNING_KEY'])

def snapshot_tables():
    result = {}
    rows = {}
    for kind in ('approvals', 'pcs', 'history'):
        records = [json.loads(json.dumps(r.asDict(recursive=True), default=str))
                   for r in spark.table('dbo.sample_usb_'+kind).limit(1001).collect()]
        if len(records) >= 1001:
            raise ValueError('Validation table scope exceeded')
        encoded = sorted(json.dumps(r, sort_keys=True, ensure_ascii=False) for r in records)
        result[kind] = {'count': len(records), 'sha256': hashlib.sha256('\n'.join(encoded).encode()).hexdigest()}
        rows[kind] = records
    return result, rows

before_tables, data = snapshot_tables()
def spark_reader(upn, serial, user_id=''):
    approvals = [r for r in data['approvals'] if r['user_upn'].lower() == upn.lower()
                 and r['usb_serial'].upper() == serial.upper()]
    if len(approvals) >= 201:
        raise SourceError('incomplete', 'fabric_rows_truncated')
    return {'approvals': approvals, 'pcs': data['pcs'], 'workspace_id': cfg['workspace_id'],
            'lakehouse_id': cfg['lakehouse_id'], 'read_method': 'Fabric Spark read-only sample_usb tables'}

def ledger_snapshot():
    with store.connect() as db:
        return {kind: store.rows(db, kind) for kind in ('approvals', 'pcs', 'history', 'pair_policy')}

before_ledger = ledger_snapshot()
sources = ReadSources(cfg['tenant_id'], sql_reader=spark_reader)
result = await LakeWorker(store, queue, read_sources=sources).run_pending_intake(limit=int(MAX_REQUESTS))
after_ledger = ledger_snapshot()
assert after_ledger['pcs'] == before_ledger['pcs'], 'PC ledger changed unexpectedly'
assert after_ledger['pair_policy'] == before_ledger['pair_policy'], 'Policy ledger changed unexpectedly'
for kind, key in (('approvals', 'approval_id'), ('history', 'event_id')):
    prior = {r[key]: r for r in before_ledger[kind]}
    current = {r[key]: r for r in after_ledger[kind]}
    assert all(current.get(k) == row for k, row in prior.items() if row.get('policy_mode') != 'usb_mtp_pairing'), 'Existing non-pairing ledger row changed unexpectedly'
after_tables, _ = snapshot_tables()
assert after_tables == before_tables, 'Source tables changed unexpectedly'
import uuid
proof = {'source': 'notebook-intake-no-policy-writes', 'processed': result['processed'],
         'outcomes': [{'request_id': r['request_id'], 'status': r['status'],
                       'decision': r.get('result', {}).get('decision'),
                       'approval_id': r.get('result', {}).get('approval_id')} for r in result['outcomes']],
         'source_tables_unchanged': True, 'existing_ledger_rows_unchanged': True,
         'approvals_added': len(after_ledger['approvals']) - len(before_ledger['approvals']),
         'graph_writes': False, 'intune_policy_changed': False,
         'trigger_source': 'See Fabric job history for Manual versus Scheduled invocation'}
files.create('verification/lookup-batch-'+uuid.uuid4().hex+'.json', canonical(proof))
print(json.dumps(proof, ensure_ascii=False))
notebookutils.notebook.exit(json.dumps(proof, ensure_ascii=False))
