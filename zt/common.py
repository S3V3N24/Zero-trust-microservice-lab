"""Shared constants, the audit log and tiny HTTP helpers used by every component."""
from __future__ import annotations

import http.client
import json
import os
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = ROOT / 'config'
RUNTIME_DIR = Path(os.environ.get('ZT_RUNTIME_DIR') or ROOT / 'runtime')
AUDIT_FILE = RUNTIME_DIR / 'audit.jsonl'
DECOY_DIR = ROOT / 'decoy_secrets'

TRUST_DOMAIN = 'cluster.local'
HOST = '127.0.0.1'

# Every port can be shifted (ZT_PORT_OFFSET) so the demo can run next to other software.
PORT_OFFSET = int(os.environ.get('ZT_PORT_OFFSET', '0'))
PORTS = {name: base + PORT_OFFSET for name, base in {
    'controlplane': 9000,   # certificate authority API ("SPIRE server")
    'dashboard': 8080,      # live web dashboard
    'gateway': 8000,        # public entry point ("ingress gateway")
    'api': 9001,            # URL shortener API    (report: fastapi-backend)
    'cache': 9002,          # key-value cache      (report: redis-cache)
    'db': 9003,             # persistent storage   (report: postgres-db)
    'baseline': 9100,       # plain HTTP server used only by the benchmark
}.items()}
CTL_OFFSET = 2000           # demo-only "compromise simulator" listens on port + 2000
SERVICES = ['db', 'cache', 'api', 'gateway']   # start order

SVID_TTL = int(os.environ.get('ZT_SVID_TTL', '30'))      # seconds (report: 1 hour)
LOG_ALLOW = os.environ.get('ZT_LOG_ALLOW', '1') == '1'   # also log allowed requests

ISSUER = 'https://auth.example.com/realms/shortener'
AUDIENCE = 'url-shortener-api'

_audit_lock = threading.Lock()


def audit(service: str, kind: str, **fields) -> None:
    """Append one JSON line to the shared audit log (read by the dashboard and the tests)."""
    record = {'ts': round(time.time(), 4), 'service': service, 'kind': kind}
    record.update(fields)
    line = json.dumps(record, default=str) + '\n'
    try:
        RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
        with _audit_lock, open(AUDIT_FILE, 'a', encoding='utf-8') as fh:
            fh.write(line)
    except OSError:
        pass


def read_audit() -> list:
    try:
        with open(AUDIT_FILE, encoding='utf-8') as fh:
            return [json.loads(x) for x in fh.read().splitlines() if x.strip()]
    except (OSError, ValueError):
        return []


def short_id(spiffe_id) -> str:
    if not spiffe_id:
        return '-'
    return spiffe_id.replace('spiffe://%s/' % TRUST_DOMAIN, '')


def load_registry() -> dict:
    """workload name -> SPIFFE ID (the registration entries of the CA)."""
    data = json.loads((CONFIG_DIR / 'registry.json').read_text(encoding='utf-8'))
    return {e['workload']: e['spiffe_id'] for e in data['entries']}


def http_json(port: int, method: str, path: str, body=None, headers=None, timeout: float = 3.0):
    """Plain-HTTP JSON call to a loopback endpoint. Returns (status, parsed_body)."""
    conn = http.client.HTTPConnection(HOST, port, timeout=timeout)
    try:
        payload = json.dumps(body).encode() if body is not None else None
        hdrs = {'Content-Type': 'application/json'}
        hdrs.update(headers or {})
        conn.request(method, path, body=payload, headers=hdrs)
        resp = conn.getresponse()
        raw = resp.read()
        try:
            return resp.status, json.loads(raw) if raw else None
        except ValueError:
            return resp.status, raw.decode(errors='replace')
    finally:
        conn.close()
