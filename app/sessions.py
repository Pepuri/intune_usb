"""Shared encrypted login flows and sessions; opaque cookie handles are hashed at rest."""
import hashlib
import json
import time
from cryptography.fernet import Fernet, InvalidToken


class SharedSessions:
    def __init__(self, store, encryption_key):
        self.store = store
        self.cipher = Fernet(encryption_key.encode())

    @staticmethod
    def key(handle):
        return hashlib.sha256(handle.encode()).hexdigest()

    def put(self, kind, handle, value):
        encrypted = self.cipher.encrypt(json.dumps(value).encode()).decode()
        with self.store.connect() as db:
            self.store.save(db, 'auth_'+kind, self.key(handle), {'ciphertext':encrypted, 'expires':value['expires']})
            for row in db.execute('SELECT id,body FROM documents WHERE kind=?', ('auth_'+kind,)).fetchall():
                if json.loads(row[1]).get('expires', 0) <= time.time():
                    db.execute('DELETE FROM documents WHERE kind=? AND id=?', ('auth_'+kind, row[0]))

    def get(self, kind, handle, consume=False):
        if not handle:
            return None
        with self.store.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row = self.store.get(db, 'auth_'+kind, self.key(handle))
            if not row:
                return None
            if consume or row['expires'] <= time.time():
                db.execute('DELETE FROM documents WHERE kind=? AND id=?', ('auth_'+kind, self.key(handle)))
            if row['expires'] <= time.time():
                return None
            try:
                return json.loads(self.cipher.decrypt(row['ciphertext'].encode()))
            except (InvalidToken, ValueError):
                return None

    def delete(self, kind, handle):
        with self.store.connect() as db:
            db.execute('DELETE FROM documents WHERE kind=? AND id=?', ('auth_'+kind, self.key(handle or '')))
