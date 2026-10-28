"""Local demo ledger. No Graph, Fabric or Azure writes are performed."""
import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class Store:
    def __init__(self, path, seed=True):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            self.initialize(db, seed)

    def initialize(self, db, seed):
        db.execute('CREATE TABLE IF NOT EXISTS documents (kind TEXT, id TEXT, body TEXT, PRIMARY KEY(kind,id))')
        db.execute('CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT)')
        if seed and not db.execute("SELECT 1 FROM metadata WHERE key='seeded'").fetchone():
            for kind, key in [('approvals', 'approval_id'), ('pcs', 'device_id'), ('history', 'event_id')]:
                rows = json.loads((ROOT / 'sample_data' / f'sample_usb_{kind}.json').read_text(encoding='utf-8-sig'))
                for row in rows:
                    row.setdefault('revision', 1)
                    self.save(db, kind, row[key], row)
            db.execute("INSERT INTO metadata VALUES ('seeded','1')")

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.execute('PRAGMA busy_timeout=10000')
        try:
            with db:
                yield db
        finally:
            db.close()

    @staticmethod
    def save(db, kind, key, body):
        db.execute('INSERT OR REPLACE INTO documents VALUES (?,?,?)', (kind, key, json.dumps(body, ensure_ascii=False)))

    @staticmethod
    def rows(db, kind):
        return [json.loads(r[0]) for r in db.execute('SELECT body FROM documents WHERE kind=? ORDER BY id', (kind,))]

    @staticmethod
    def get(db, kind, key):
        row = db.execute('SELECT body FROM documents WHERE kind=? AND id=?', (kind, key)).fetchone()
        return json.loads(row[0]) if row else None


def get_store(path=None):
    from .runtime import cloud_mode
    if path is not None:
        return Store(path)
    if cloud_mode():
        from .onelake import OneLakeStore
        return OneLakeStore.from_env('ledger')
    import os
    return Store(os.getenv('USB_DEMO_DB', str(ROOT/'.data/demo.sqlite3')))
