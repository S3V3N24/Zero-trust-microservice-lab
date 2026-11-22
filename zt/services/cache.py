"""Key-value cache (report: redis-cache). Only the API identity may use it (policy cache-from-api)."""
import json
import threading

from ..mesh import MeshService


class CacheApp:
    name = 'cache'
    tls = True

    def __init__(self):
        self.store, self.lock = {}, threading.Lock()

    def authenticate(self, svc, req, headers):
        return None

    def handle(self, svc, req, body, headers, raw_path):
        if req.path.startswith('/kv/'):
            key = req.path[len('/kv/'):]
            if req.method == 'GET':
                with self.lock:
                    if key in self.store:
                        return 200, {'value': self.store[key]}
                return 404, {'error': 'miss'}
            if req.method == 'PUT':
                value = json.loads(body or b'{}').get('value')
                with self.lock:
                    self.store[key] = value
                return 200, {'stored': key}
        return 404, {'error': 'not found'}


if __name__ == '__main__':
    MeshService(CacheApp()).run()
