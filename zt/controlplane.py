"""Control plane: certificate authority API ("SPIRE server") and the live dashboard."""
from __future__ import annotations

import json
import os
import socketserver
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from .ca import AttestationError, CertificateAuthority
from .common import (AUDIT_FILE, CTL_OFFSET, HOST, PORTS, SERVICES, SVID_TTL, ROOT, audit,
                     http_json, load_registry, short_id)

CA = None
ADMIN_TOKEN = os.environ.get('ZT_ADMIN_TOKEN', '')


class _Server(ThreadingHTTPServer):
    daemon_threads = True

    def server_bind(self):          # skip the slow reverse-DNS lookup done by HTTPServer
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = HOST, self.server_address[1]


class _Quiet(BaseHTTPRequestHandler):
    disable_nagle_algorithm = True

    def log_message(self, *args):
        pass

    def reply(self, status, payload, ctype='application/json'):
        data = payload.encode() if isinstance(payload, str) else json.dumps(payload).encode()
        self.send_response(status)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def json_body(self):
        length = int(self.headers.get('Content-Length') or 0)
        try:
            return json.loads(self.rfile.read(length) or b'{}')
        except ValueError:
            return {}


class CAHandler(_Quiet):
    def do_GET(self):
        if self.path == '/bundle':
            return self.reply(200, CA.bundle_pem, 'text/plain')
        if self.path == '/revoked':
            return self.reply(200, {'revoked': CA.revoked_ids()})
        self.reply(404, {'error': 'not found'})

    def do_POST(self):
        body = self.json_body()
        if self.path == '/svid':
            try:
                result = CA.issue(body.get('workload', ''), body.get('token', ''), body.get('csr', ''))
            except AttestationError as exc:
                audit('controlplane', 'identity', event='denied', workload=body.get('workload'), reason=str(exc))
                return self.reply(403, {'error': str(exc)})
            except Exception as exc:
                return self.reply(400, {'error': 'bad request: %s' % exc})
            return self.reply(200, result)
        if self.path == '/revoke':        # a workload's sentinel reports its own compromise
            try:
                spiffe_id = CA.attest(body.get('workload', ''), body.get('token', ''))
            except AttestationError as exc:
                return self.reply(403, {'error': str(exc)})
            CA.revoke(spiffe_id, body.get('reason', 'reported by sentinel'))
            audit('controlplane', 'identity', event='revoked', spiffe_id=short_id(spiffe_id), reason=body.get('reason'))
            return self.reply(200, {'revoked': spiffe_id})
        if self.path == '/release':       # operator releases a quarantined workload
            if self.headers.get('X-Admin-Token') != ADMIN_TOKEN or not ADMIN_TOKEN:
                return self.reply(403, {'error': 'admin token required'})
            spiffe_id = load_registry().get(body.get('workload', ''))
            if not spiffe_id:
                return self.reply(404, {'error': 'unknown workload'})
            CA.release(spiffe_id)
            audit('controlplane', 'identity', event='released', spiffe_id=short_id(spiffe_id))
            return self.reply(200, {'released': spiffe_id})
        self.reply(404, {'error': 'not found'})


class DashboardHandler(_Quiet):
    def do_GET(self):
        parsed = urlsplit(self.path)
        if parsed.path == '/':
            return self.reply(200, (ROOT / 'zt' / 'dashboard.html').read_text(encoding='utf-8'), 'text/html; charset=utf-8')
        if parsed.path == '/api/events':
            since = int((parse_qs(parsed.query).get('since') or ['0'])[0])
            try:
                lines = AUDIT_FILE.read_text(encoding='utf-8').splitlines()
            except OSError:
                lines = []
            events = []
            for line in lines[since:]:
                try:
                    events.append(json.loads(line))
                except ValueError:
                    pass
            return self.reply(200, {'events': events, 'next': len(lines)})
        if parsed.path == '/api/status':
            out = []
            for name in SERVICES:
                try:
                    status, data = http_json(PORTS[name] + CTL_OFFSET, 'GET', '/status', timeout=0.5)
                    out.append(data if status == 200 else {'name': name, 'down': True})
                except OSError:
                    out.append({'name': name, 'down': True})
            return self.reply(200, {'services': out, 'now': time.time(), 'revoked': CA.revoked_ids(), 'ttl': SVID_TTL})
        self.reply(404, {'error': 'not found'})


def main():
    global CA
    CA = CertificateAuthority(load_registry(), os.environ['ZT_NODE_SECRET'], SVID_TTL)
    ca_server = _Server((HOST, PORTS['controlplane']), CAHandler)
    dash_server = _Server((HOST, PORTS['dashboard']), DashboardHandler)
    threading.Thread(target=dash_server.serve_forever, daemon=True).start()
    audit('controlplane', 'service', event='started', port=PORTS['controlplane'], detail='certificate authority online')
    try:
        ca_server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
