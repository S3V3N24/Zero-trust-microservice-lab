"""URL shortener API (report: fastapi-backend). Reached only through the gateway; talks to cache and db."""
import json
import re
import secrets
from urllib.parse import urlsplit

from ..mesh import MeshService

ALPHABET = 'abcdefghijklmnopqrstuvwxyz0123456789'


class ApiApp:
    name = 'api'
    tls = True

    def __init__(self):
        self.counters = {'created': 0, 'cache_hits': 0, 'db_hits': 0}

    def authenticate(self, svc, req, headers):
        return None

    def handle(self, svc, req, body, headers, raw_path):
        # NOTE: /healthz must be matched BEFORE the catch-all alias route (the report, Section 4.9)
        if req.method == 'GET' and req.path == '/healthz':
            return 200, {'status': 'ok'}
        if req.method == 'GET' and req.path == '/internal/stats':
            return 200, dict(self.counters)
        if req.method == 'POST' and req.path == '/shorten':
            return self.shorten(svc, body)
        if req.method == 'GET' and re.fullmatch(r'/[A-Za-z0-9_-]{3,32}', req.path):
            return self.resolve(svc, req.path[1:])
        return 404, {'error': 'not found'}

    def shorten(self, svc, body):
        data = json.loads(body or b'{}')
        url = data.get('original_url', '')
        parts = urlsplit(url)
        if parts.scheme not in ('http', 'https') or not parts.netloc:
            return 400, {'error': 'original_url must be an http(s) URL'}
        alias = data.get('custom_alias') or ''.join(secrets.choice(ALPHABET) for _ in range(6))
        status, payload = svc.call('db', 'POST', '/urls', {'alias': alias, 'original_url': url})
        if status == 409:
            return 400, {'error': 'Custom alias already exists'}
        if status != 201:
            return 502, {'error': 'database refused the request', 'status': status}
        svc.call('cache', 'PUT', '/kv/' + alias, {'value': url})
        self.counters['created'] += 1
        return 201, {'short_url': 'http://localhost:8000/' + alias, 'alias': alias}

    def resolve(self, svc, alias):
        status, payload = svc.call('cache', 'GET', '/kv/' + alias)
        if status == 200:
            self.counters['cache_hits'] += 1
            return 200, {'redirect_to': payload['value'], 'source': 'cache'}
        status, payload = svc.call('db', 'GET', '/urls/' + alias)
        if status == 200:
            svc.call('cache', 'PUT', '/kv/' + alias, {'value': payload['original_url']})
            self.counters['db_hits'] += 1
            return 200, {'redirect_to': payload['original_url'], 'source': 'database'}
        return 404, {'error': 'Alias not found'}


if __name__ == '__main__':
    MeshService(ApiApp()).run()
