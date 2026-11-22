"""Persistent storage (report: postgres-db), implemented with SQLite. Only the API identity may use it."""
import json
import sqlite3
import threading
import time

from ..common import RUNTIME_DIR
from ..mesh import MeshService


class DbApp:
    name = 'db'
    tls = True

    def __init__(self):
        RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()
        self.conn = sqlite3.connect(str(RUNTIME_DIR / 'urls.db'), check_same_thread=False)
        self.conn.execute('CREATE TABLE IF NOT EXISTS urls '
                          '(alias TEXT PRIMARY KEY, original_url TEXT NOT NULL, created_at REAL)')
        self.conn.commit()

    def authenticate(self, svc, req, headers):
        return None

    def handle(self, svc, req, body, headers, raw_path):
        if req.method == 'POST' and req.path == '/urls':
            data = json.loads(body or b'{}')
            try:
                with self.lock:
                    self.conn.execute('INSERT INTO urls (alias, original_url, created_at) VALUES (?, ?, ?)',
                                      (data['alias'], data['original_url'], time.time()))
                    self.conn.commit()
            except sqlite3.IntegrityError:
                return 409, {'error': 'alias already exists'}
            return 201, {'created': data['alias']}
        if req.method == 'GET' and req.path.startswith('/urls/'):
            alias = req.path[len('/urls/'):]
            with self.lock:
                row = self.conn.execute('SELECT original_url FROM urls WHERE alias = ?', (alias,)).fetchone()
            return (200, {'original_url': row[0]}) if row else (404, {'error': 'not found'})
        return 404, {'error': 'not found'}


if __name__ == '__main__':
    MeshService(DbApp()).run()
