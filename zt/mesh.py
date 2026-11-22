"""The "sidecar": mutual TLS, identity checks and policy enforcement for every service.

In the report this job is done by an Envoy proxy next to each pod. Here every service
process embeds the same logic so the whole system stays a plain Python program.

Server side, for every incoming connection and request:
  1. TLS 1.3 handshake that REQUIRES a client certificate signed by our CA (strict mTLS)
  2. read the caller's SPIFFE ID from the certificate
  3. reject callers whose identity has been revoked, refuse everything while quarantined
  4. evaluate the authorization policy (DENY, then ALLOW, default deny)
  5. only then call the application code
Client side: connect with our own certificate and verify that the server presents the
SPIFFE ID we expect for the destination.
"""
from __future__ import annotations

import http.client
import io
import json
import os
import socketserver
import ssl
import threading
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from .common import (CTL_OFFSET, DECOY_DIR, HOST, LOG_ALLOW, PORTS, audit, http_json,
                     load_registry, short_id)
from .identity import WorkloadIdentity, peer_spiffe_id
from .policy import Request, decide, load_policies
from .sentinel import Sentinel


class MeshError(Exception):
    pass


# ---------------------------------------------------------------------------------------
# client side
# ---------------------------------------------------------------------------------------
def mesh_request(identity, dest: str, method: str, path: str, body=None, headers=None, timeout: float = 5.0):
    """Call another service over mTLS. Returns (status, parsed JSON body)."""
    expected = load_registry()[dest]
    conn = http.client.HTTPSConnection(HOST, PORTS[dest], context=identity.client_context, timeout=timeout)
    try:
        conn.connect()
        got = peer_spiffe_id(conn.sock)
        if got != expected:
            raise MeshError('server identity mismatch: expected %s, got %s' % (expected, got))
        payload = json.dumps(body).encode() if isinstance(body, (dict, list)) else body
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


# ---------------------------------------------------------------------------------------
# server side
# ---------------------------------------------------------------------------------------
class _Server(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 128

    def server_bind(self):                       # avoid the slow reverse-DNS lookup of HTTPServer
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = HOST, self.server_address[1]


def _make_handler(svc: 'MeshService'):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'
        wbufsize = 65536                  # send headers + body in one write (avoids Nagle / delayed-ACK stalls)
        disable_nagle_algorithm = True

        def setup(self):
            self.peer, self.failed = None, False
            if svc.app.tls:
                try:
                    self.request.settimeout(5)
                    self.request = svc.identity.server_context.wrap_socket(self.request, server_side=True)
                    self.request.settimeout(30)
                    self.peer = peer_spiffe_id(self.request)
                except (ssl.SSLError, OSError) as exc:
                    self.failed = True
                    reason = getattr(exc, 'reason', None) or str(exc)
                    if reason != 'UNEXPECTED_EOF_WHILE_READING':        # a bare port probe, not an attack
                        svc.count('handshake_rejected')
                        audit(svc.name, 'handshake', allowed=False, reason=str(reason)[:120],
                              detail='TLS handshake rejected (no valid client certificate)')
            if self.failed:
                self.rfile, self.wfile, self.connection = io.BytesIO(), io.BytesIO(), self.request
            else:
                super().setup()

        def finish(self):
            super().finish()
            if svc.app.tls and not self.failed:
                try:
                    self.request.close()
                except OSError:
                    pass

        def log_message(self, *args):
            pass

        def _send(self, status, payload):
            data = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(data)))
            self.send_header('X-ZT-Service', svc.name)
            self.end_headers()
            self.wfile.write(data)

        def _serve(self):
            if self.failed:
                return
            length = int(self.headers.get('Content-Length') or 0)
            body = self.rfile.read(length) if length else b''
            path = urlsplit(self.path).path
            req = Request(principal=self.peer, method=self.command, path=path)
            try:
                if svc.quarantined:
                    svc.count('quarantined_rejects')
                    return self._send(503, {'error': 'workload quarantined by the runtime sentinel'})
                if svc.app.tls:
                    if self.peer is None:
                        return self._deny(req, 'no client identity')
                    if self.peer in svc.revoked:
                        return self._deny(req, 'caller identity has been revoked')
                early = svc.app.authenticate(svc, req, self.headers)
                if early is not None:
                    return self._send(*early)
                decision = decide(svc.name, req, svc.policies)
                if not decision.allowed:
                    return self._deny(req, decision.reason, decision.policy)
                svc.count('allowed')
                if LOG_ALLOW:
                    audit(svc.name, 'decision', allowed=True, caller=short_id(req.principal), user=req.user,
                          method=req.method, path=path, reason=decision.reason)
                status, payload = svc.app.handle(svc, req, body, self.headers, self.path)
                self._send(status, payload)
            except Exception as exc:               # never leak a stack trace to the caller
                audit(svc.name, 'error', detail=repr(exc)[:200])
                traceback.print_exc()
                self._send(500, {'error': 'internal error'})

        def _deny(self, req, reason, policy=None):
            svc.count('denied')
            audit(svc.name, 'decision', allowed=False, caller=short_id(req.principal), user=req.user,
                  method=req.method, path=req.path, reason=reason, policy=policy)
            self._send(403, {'error': 'RBAC: access denied', 'reason': reason})

        do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = _serve

    return Handler


class MeshService:
    """Runs one application behind the zero-trust "sidecar"."""

    def __init__(self, app):
        self.app = app
        self.name = app.name
        self.port = PORTS[self.name]
        self.token = os.environ.get('ZT_ATTEST_TOKEN', '')
        self.policies = load_policies()
        self.identity = WorkloadIdentity(self.name, self.token)
        self.sentinel = Sentinel(self.name, self._on_critical)
        self.revoked: set = set()
        self.quarantined = False
        self._q_pending = False
        self._stats = {'allowed': 0, 'denied': 0, 'handshake_rejected': 0, 'quarantined_rejects': 0}
        self._stats_lock = threading.Lock()

    def count(self, key: str) -> None:
        with self._stats_lock:
            self._stats[key] = self._stats.get(key, 0) + 1

    def call(self, dest, method, path, body=None, headers=None):
        return mesh_request(self.identity, dest, method, path, body, headers)

    # ---- automatic response ------------------------------------------------------------
    def _on_critical(self, rule: str) -> None:
        self.quarantined = True
        self._q_pending = True
        threading.Thread(target=self._revoke_self, args=(rule,), daemon=True).start()

    def _revoke_self(self, rule: str) -> None:
        while True:
            try:
                status, _ = http_json(PORTS['controlplane'], 'POST', '/revoke',
                                      {'workload': self.name, 'token': self.token, 'reason': rule})
                if status == 200:
                    audit(self.name, 'response', action='quarantine+revoke', detail='identity revoked after: ' + rule)
                    break
            except OSError:
                pass
            time.sleep(0.5)
        self._q_pending = False

    def _poll_revocations(self) -> None:
        while True:
            try:
                status, data = http_json(PORTS['controlplane'], 'GET', '/revoked', timeout=2)
                if status == 200:
                    self.revoked = set(data['revoked'])
                    if not self._q_pending:
                        self.quarantined = self.identity.spiffe_id in self.revoked
            except OSError:
                pass
            time.sleep(0.4)

    # ---- demo-only compromise simulator ------------------------------------------------
    def _ctl_server(self) -> None:
        svc = self

        class Ctl(BaseHTTPRequestHandler):
            disable_nagle_algorithm = True

            def log_message(self, *a):
                pass

            def _reply(self, status, payload):
                data = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                if self.path == '/status':
                    ident = svc.identity
                    return self._reply(200, {
                        'name': svc.name, 'spiffe_id': ident.spiffe_id, 'serial': ident.serial,
                        'not_after': ident.not_after, 'quarantined': svc.quarantined,
                        'revoked_seen': sorted(svc.revoked), 'stats': dict(svc._stats)})
                self._reply(404, {'error': 'not found'})

            def do_POST(self):
                parsed = urlsplit(self.path)
                if parsed.path != '/attack':
                    return self._reply(404, {'error': 'not found'})
                action = (parse_qs(parsed.query).get('action') or [''])[0]
                actions = svc._attack_actions()
                if action not in actions:
                    return self._reply(400, {'error': 'unknown action', 'allowed': sorted(actions)})
                try:
                    self._reply(200, {'action': action, 'outcome': actions[action]()})
                except Exception as exc:
                    self._reply(200, {'action': action, 'outcome': 'blocked: %s' % exc})

        server = _Server((HOST, self.port + CTL_OFFSET), Ctl)
        threading.Thread(target=server.serve_forever, daemon=True).start()

    def _attack_actions(self) -> dict:
        """DEMO ONLY. A fixed whitelist of what an attacker who has code execution inside this
        process might try. There is deliberately no way to run an arbitrary command."""
        import socket
        import subprocess

        def shell():
            cmd = ['cmd', '/c', 'echo zta-demo'] if os.name == 'nt' else ['sh', '-c', 'echo zta-demo']
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            return 'executed (output: %s)' % out.stdout.strip()

        def credential():
            with open(DECOY_DIR / 'service-account-token') as fh:
                return 'executed (read %d bytes of a decoy file)' % len(fh.read())

        def egress():
            socket.create_connection(('192.0.2.10', 3333), timeout=2)    # RFC 5737 documentation address
            return 'executed'

        def call(dest, path):
            def run():
                status, _ = self.call(dest, 'GET', path)
                return 'HTTP %s' % status
            return run

        return {'shell': shell, 'credential': credential, 'egress': egress,
                'lateral_db': call('db', '/urls/probe'), 'lateral_api': call('api', '/healthz'),
                'call_cache': call('cache', '/kv/probe')}

    # ---- run ---------------------------------------------------------------------------
    def run(self) -> None:
        self.sentinel.install()
        self.identity.start()
        threading.Thread(target=self._poll_revocations, daemon=True).start()
        self._ctl_server()
        server = _Server((HOST, self.port), _make_handler(self))
        audit(self.name, 'service', event='started', port=self.port, spiffe_id=short_id(self.identity.spiffe_id))
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
