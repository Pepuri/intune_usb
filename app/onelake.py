"""OneLake Files persistence. SQLite is an ephemeral transaction engine, never a hosted DB."""
from contextlib import contextmanager
from contextvars import ContextVar
import json
import os
import re
import sqlite3
import threading
import time
from uuid import UUID, uuid4

from azure.core import MatchConditions
from azure.core.exceptions import ResourceExistsError, ResourceNotFoundError, ResourceModifiedError
from azure.identity import ManagedIdentityCredential
from azure.storage.blob import BlobServiceClient
from .store import Store

SCHEMA = {
    'documents': 'kind TEXT, id TEXT, body TEXT, PRIMARY KEY(kind,id)',
    'metadata': 'key TEXT PRIMARY KEY, value TEXT',
    'jobs': '''id TEXT PRIMARY KEY, dedupe TEXT UNIQUE, kind TEXT, payload TEXT, status TEXT,
              attempts INTEGER, max_attempts INTEGER, available REAL, lease_until REAL, lease_token TEXT,
              error TEXT, created TEXT, updated TEXT, result TEXT''',
    'job_runs': 'id TEXT PRIMARY KEY, job_id TEXT, attempt INTEGER, started TEXT, finished TEXT, status TEXT, source TEXT, error TEXT',
    'bridge_nonces': 'nonce TEXT PRIMARY KEY, expires INTEGER',
}


class LakeFiles:
    def __init__(self, container, prefix):
        self.container = container
        self.prefix = prefix.rstrip('/')+'/'

    @classmethod
    def from_env(cls, credential=None):
        ws = str(UUID(os.environ['USB_ONELAKE_WORKSPACE_ID']))
        lh = str(UUID(os.environ['USB_ONELAKE_LAKEHOUSE_ID']))
        prefix = os.getenv('USB_ONELAKE_PREFIX','usb-operations')
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,80}',prefix):
            raise ValueError('Invalid OneLake application folder')
        credential = credential or ManagedIdentityCredential(client_id=os.getenv('AZURE_CLIENT_ID') or None)
        service = BlobServiceClient('https://onelake.blob.fabric.microsoft.com', credential=credential,
                                   retry_total=2, connection_timeout=10, read_timeout=30)
        return cls(service.get_container_client(ws), f'{lh}/Files/{prefix}')

    def blob(self, name):
        if name.startswith('/') or '..' in name.split('/') or '\\' in name:
            raise ValueError('Unsafe OneLake file path')
        return self.container.get_blob_client(self.prefix+name)

    def read(self, name):
        try:
            return self.blob(name).download_blob().readall()
        except ResourceNotFoundError:
            return None

    def create(self, name, raw):
        try:
            self.blob(name).upload_blob(raw, overwrite=False)
            return True
        except ResourceExistsError:
            return False

    def names(self, prefix):
        return [p.name[len(self.prefix):] for p in self.container.list_blobs(name_starts_with=self.prefix+prefix)]


class Transaction:
    def __init__(self, db):
        self.db = db

    @property
    def row_factory(self):
        return self.db.row_factory

    @row_factory.setter
    def row_factory(self, value):
        self.db.row_factory = value

    def execute(self, sql, parameters=()):
        if sql == 'BEGIN IMMEDIATE' and self.db.in_transaction:
            return self.db.execute('SELECT 1')
        return self.db.execute(sql, parameters)

    def commit(self):
        # The outer OneLake transaction publishes state and command receipt together.
        pass


class OneLakeStore(Store):
    def __init__(self, files, name='ledger'):
        if name not in ('ledger','auth'):
            raise ValueError('Unknown state namespace')
        self.files, self.name, self.path = files, name, None
        self.current = ContextVar('lake_transaction_'+name, default=None)
        self.local_lock = threading.RLock()
        with self.connect() as db:
            self.initialize(db, seed=False)

    @classmethod
    def from_env(cls, name='ledger'):
        return cls(LakeFiles.from_env(), name)

    @contextmanager
    def connect(self):
        current = self.current.get()
        if current is not None:
            name='nested_'+uuid4().hex
            current.execute('SAVEPOINT '+name)
            try:
                yield current
            except BaseException:
                current.execute('ROLLBACK TO SAVEPOINT '+name)
                current.execute('RELEASE SAVEPOINT '+name)
                raise
            else:
                current.execute('RELEASE SAVEPOINT '+name)
            return
        with self.local_lock:
            blob = self.files.blob(f'state/{self.name}.json')
            if not blob.exists():
                try:
                    self.files.create(f'state/{self.name}.json', b'{"format":1,"version":0,"tables":{}}')
                except ResourceModifiedError:
                    if not blob.exists():
                        raise
            deadline = time.monotonic()+15
            while True:
                try:
                    lease = blob.acquire_lease(lease_duration=60)
                    break
                except Exception as error:
                    if getattr(error,'status_code',None) != 409 or time.monotonic() >= deadline:
                        raise RuntimeError('OneLake state lock unavailable') from None
                    time.sleep(.1)
            stopped, lost = threading.Event(), threading.Event()
            def renew():
                while not stopped.wait(15):
                    try:
                        lease.renew()
                    except Exception:
                        lost.set()
                        return
            worker = threading.Thread(target=renew, daemon=True)
            worker.start()
            db = sqlite3.connect(':memory:', check_same_thread=False)
            token = None
            try:
                download = blob.download_blob(lease=lease)
                if download.size>32*1024*1024:
                    raise ValueError('State exceeds 32 MiB')
                snapshot = json.loads(download.readall())
                etag = download.properties.etag
                if snapshot.get('format') != 1 or not isinstance(snapshot.get('tables'),dict):
                    raise ValueError('Invalid OneLake state format')
                for table, rows in snapshot['tables'].items():
                    if table not in SCHEMA:
                        raise ValueError('Unknown state table')
                    db.execute(f'CREATE TABLE {table} ({SCHEMA[table]})')
                    for row in rows:
                        marks=','.join('?' for _ in row)
                        db.execute(f'INSERT INTO {table} VALUES ({marks})',row)
                db.commit()
                before = db.total_changes
                before_schema = tuple(r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"))
                db.execute('BEGIN IMMEDIATE')
                tx = Transaction(db)
                token = self.current.set(tx)
                yield tx
                if lost.is_set():
                    raise RuntimeError('OneLake state lease was lost; state was not committed')
                tables = tuple(r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"))
                if db.total_changes != before or tables != before_schema:
                    if any(table not in SCHEMA for table in tables):
                        raise ValueError('Unexpected state table')
                    body = {'format':1,'version':snapshot['version']+1,
                            'tables':{table:[list(row) for row in db.execute('SELECT * FROM '+table)] for table in tables}}
                    raw = json.dumps(body,ensure_ascii=False,separators=(',',':')).encode()
                    if len(raw)>32*1024*1024:
                        raise ValueError('State exceeds 32 MiB; partition/archive before continuing')
                    blob.upload_blob(raw, overwrite=True, lease=lease, etag=etag,
                                     match_condition=MatchConditions.IfNotModified)
            finally:
                if token is not None:
                    self.current.reset(token)
                db.close()
                stopped.set()
                worker.join(timeout=2)
                try:
                    lease.release()
                except Exception:
                    pass
