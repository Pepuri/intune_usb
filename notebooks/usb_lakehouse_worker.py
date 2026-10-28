# %% [markdown]
# USB 운영 — Lakehouse Files 정기 처리
# 기본 레이크하우스를 연결하고 아래 매개변수를 설정합니다.
# 별도 Fabric Environment에 requirements.txt의 패키지를 준비합니다.
# 이 소스는 로컬에서 작성만 했으며 실제 Fabric에 업로드하거나 실행하지 않았습니다.

# %% parameters
KEY_VAULT_URI = ""
REQUEST_SIGNING_SECRET_NAME = "usb-request-signing-key"
GRAPH_CLIENT_ID = ""
GRAPH_CLIENT_SECRET_NAME = "usb-graph-client-secret"
TENANT_ID = ""
APP_FOLDER = "usb-operations"
TABLE_SCHEMA = "dbo"  # 스키마 없는 Lakehouse이면 빈 문자열
MAX_REQUESTS = 50
ENABLE_SAMPLE_POLICY_WRITES = False
IMPORT_EXISTING_SAMPLE_TABLES = False  # 초기 1회만 켭니다. 기존 원장이 있으면 중단합니다.

# %%
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

context = notebookutils.runtime.context
workspace_id = context["defaultLakehouseWorkspaceId"]
lakehouse_id = context["defaultLakehouseId"]
if not workspace_id or not lakehouse_id:
    raise ValueError("기본 레이크하우스를 연결해 주세요.")
if not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", APP_FOLDER):
    raise ValueError("잘못된 앱 폴더")
if not KEY_VAULT_URI.startswith("https://") or not TENANT_ID or not GRAPH_CLIENT_ID:
    raise ValueError("Key Vault와 테넌트·조회 앱 ID를 먼저 설정해 주세요.")

# 감사한 소스 ZIP을 이 경로에 수동 업로드한 후 실행합니다. 비밀 설정은 ZIP에 넣지 않습니다.
source_zip = Path(f"/lakehouse/default/Files/{APP_FOLDER}/code/source.zip")
runtime_dir = Path(tempfile.mkdtemp(prefix="usb-notebook-"))
with zipfile.ZipFile(source_zip) as package:
    for entry in package.infolist():
        target = (runtime_dir / entry.filename).resolve()
        if not target.is_relative_to(runtime_dir.resolve()):
            raise ValueError("안전하지 않은 소스 패키지 경로")
    package.extractall(runtime_dir)
sys.path.insert(0, str(runtime_dir))

os.environ.update({
    "USB_RUNTIME_MODE":"azure",
    "ENTRA_TENANT_ID":TENANT_ID,
    "USB_ONELAKE_WORKSPACE_ID":str(workspace_id),
    "USB_ONELAKE_LAKEHOUSE_ID":str(lakehouse_id),
    "USB_ONELAKE_PREFIX":APP_FOLDER,
    "USB_SOURCE_AUTH":"client_secret",
    "ENTRA_CLIENT_ID":GRAPH_CLIENT_ID,
    "ENTRA_CLIENT_SECRET":notebookutils.credentials.getSecret(KEY_VAULT_URI, GRAPH_CLIENT_SECRET_NAME),
    "USB_REQUEST_SIGNING_KEY":notebookutils.credentials.getSecret(KEY_VAULT_URI, REQUEST_SIGNING_SECRET_NAME),
    "USB_CLOUD_SAMPLE_WRITES":"1" if ENABLE_SAMPLE_POLICY_WRITES else "0",
    "USB_PAIR_POLICY_WRITES":"1" if ENABLE_SAMPLE_POLICY_WRITES else "0",
    "USB_PAIR_POLICY_AUTO_PUBLISH":"1" if ENABLE_SAMPLE_POLICY_WRITES else "0",
    "USB_SAMPLE_GROUP_WRITES":"1" if ENABLE_SAMPLE_POLICY_WRITES else "0",
})

class NotebookStorageCredential:
    def get_token(self, *scopes, **kwargs):
        if any(scope.rstrip("/") != "https://storage.azure.com/.default" for scope in scopes):
            raise ValueError("Storage audience only")
        return AccessToken(notebookutils.credentials.getToken("storage"), int(time.time()) + 300)

from app.onelake import LakeFiles, OneLakeStore
from usb_functions.lake_queue import LakeQueue
from usb_functions.lake_worker import LakeWorker

files = LakeFiles.from_env(credential=NotebookStorageCredential())
store = OneLakeStore(files)
queue = LakeQueue(files, os.environ["USB_REQUEST_SIGNING_KEY"])
if IMPORT_EXISTING_SAMPLE_TABLES:
    if TABLE_SCHEMA and not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", TABLE_SCHEMA):
        raise ValueError("잘못된 스키마")
    source_prefix = f"{TABLE_SCHEMA}." if TABLE_SCHEMA else ""
    initial = {}
    for kind in ("approvals", "pcs", "history"):
        initial[kind] = [json.loads(json.dumps(row.asDict(recursive=True),default=str))
                         for row in spark.table(source_prefix+"sample_usb_"+kind).toLocalIterator()]
        if any(row.get("is_sample") is not True for row in initial[kind]):
            raise ValueError("샘플 표시 없는 원본은 자동으로 가져오지 않습니다.")
    with store.connect() as db:
        if any(store.rows(db,kind) for kind in initial):
            raise ValueError("기존 앱 원장이 있어 초기 적재를 중단합니다.")
        for kind, id_key in (("approvals","approval_id"),("pcs","device_id"),("history","event_id")):
            for row in initial[kind]:
                row.setdefault("revision",1)
                store.save(db,kind,row[id_key],row)
result = await LakeWorker(store, queue).run(limit=int(MAX_REQUESTS))
# 요청 원문·개인정보·토큰은 출력하지 않습니다.
print({"processed":result["processed"], "source":"scheduled-notebook"})

# %%
# 분석용 Delta 테이블은 원본 Files 상태에서 만든 사본입니다. 기존 sample_usb_*는 수정하지 않습니다.
if TABLE_SCHEMA and not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", TABLE_SCHEMA):
    raise ValueError("잘못된 테이블 스키마")
if TABLE_SCHEMA:
    spark.sql(f"SHOW TABLES IN `{TABLE_SCHEMA}`").collect()  # 기존 스키마 검증
prefix = f"{TABLE_SCHEMA}." if TABLE_SCHEMA else ""
included = {"approvals","pcs","history","pair_policy","pair_policy_events","command_receipts"}
with store.connect() as db:
    rows = [(kind,key,body) for kind,key,body in db.execute("SELECT kind,id,body FROM documents").fetchall()
            if kind in included]
    jobs = [(key,status,body) for key,status,body in db.execute("SELECT id,status,result FROM jobs").fetchall()]
spark.createDataFrame(rows, "kind string, id string, body string").write.format("delta").mode("overwrite").saveAsTable(prefix+"usb_app_documents")
spark.createDataFrame(jobs, "id string, status string, result string").write.format("delta").mode("overwrite").saveAsTable(prefix+"usb_app_jobs")
# 노트북/파이프라인을 주기 실행하도록 나중에 설정합니다. 여기서는 세션을 종료하지 않습니다.
