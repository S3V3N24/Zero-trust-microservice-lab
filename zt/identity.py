"""Workload-side identity client (the role of the SPIRE agent + Envoy SDS in the report).

Each workload generates its own key pair, asks the CA for a certificate, keeps the private
key only in memory (key files exist for a few milliseconds while OpenSSL loads them), and
renews the certificate automatically at half of its lifetime (report Section 3.12).
"""
from __future__ import annotations

import os
import ssl
import tempfile
import threading
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from .common import HOST, PORTS, audit, http_json, short_id


class IdentityError(Exception):
    pass


def peer_spiffe_id(sock):
    """SPIFFE ID (URI SAN) of the peer certificate of a TLS socket, or None."""
    try:
        cert = sock.getpeercert()
    except (ValueError, OSError):
        return None
    if not cert:
        return None
    for kind, value in cert.get('subjectAltName', ()):
        if kind == 'URI' and value.startswith('spiffe://'):
            return value
    return None


def build_context(server: bool, cert_pem: str, key_pem: str, bundle_pem: str,
                  min_version=ssl.TLSVersion.TLSv1_3, max_version=None) -> ssl.SSLContext:
    """TLS context that presents our SVID and only trusts the CA bundle. TLS 1.3 minimum."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if server else ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = min_version
    if max_version is not None:
        ctx.maximum_version = max_version
    with tempfile.TemporaryDirectory() as tmp:
        cert_path, key_path = os.path.join(tmp, 'c.pem'), os.path.join(tmp, 'k.pem')
        with open(cert_path, 'w') as fh:
            fh.write(cert_pem)
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT, 0o600)
        with os.fdopen(fd, 'w') as fh:
            fh.write(key_pem)
        ctx.load_cert_chain(cert_path, key_path)
    ctx.load_verify_locations(cadata=bundle_pem)
    if not server:
        ctx.check_hostname = False        # SPIFFE authenticates the identity (URI SAN), not a hostname
    ctx.verify_mode = ssl.CERT_REQUIRED   # mutual TLS: both sides must present a valid SVID
    return ctx


class WorkloadIdentity:
    def __init__(self, workload: str, token: str, ca_port: int | None = None, name: str | None = None):
        self.workload = workload
        self.token = token
        self.ca_port = ca_port or PORTS['controlplane']
        self.log_name = name or workload
        self.spiffe_id = None
        self.serial = None
        self.not_after = 0.0
        self.not_before = 0.0
        self._state = None
        self._stop = threading.Event()

    # ---- public API --------------------------------------------------------------------
    def start(self) -> 'WorkloadIdentity':
        self.refresh()
        threading.Thread(target=self._rotate_loop, daemon=True, name='svid-rotation').start()
        return self

    def stop(self) -> None:
        self._stop.set()

    @property
    def server_context(self) -> ssl.SSLContext:
        return self._state['server']

    @property
    def client_context(self) -> ssl.SSLContext:
        return self._state['client']

    def custom_client_context(self, **kwargs) -> ssl.SSLContext:
        s = self._state
        return build_context(False, s['cert_pem'], s['key_pem'], s['bundle_pem'], **kwargs)

    # ---- internals ---------------------------------------------------------------------
    def refresh(self) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        csr = (x509.CertificateSigningRequestBuilder()
               .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, self.workload)]))
               .sign(key, hashes.SHA256()))
        try:
            status, resp = http_json(self.ca_port, 'POST', '/svid', {
                'workload': self.workload, 'token': self.token,
                'csr': csr.public_bytes(serialization.Encoding.PEM).decode()})
        except OSError as exc:
            raise IdentityError('certificate authority unreachable: %s' % exc)
        if status != 200:
            raise IdentityError((resp or {}).get('error', 'HTTP %s' % status))
        key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption()).decode()
        state = {'cert_pem': resp['cert'], 'key_pem': key_pem, 'bundle_pem': resp['bundle']}
        material = dict(state)
        state['server'] = build_context(True, **material)
        state['client'] = build_context(False, **material)
        first = self.serial is None
        self._state = state
        self.spiffe_id, self.serial = resp['spiffe_id'], resp['serial']
        self.not_before, self.not_after = resp['not_before'], resp['not_after']
        audit(self.log_name, 'identity', event='issued' if first else 'rotated',
              spiffe_id=short_id(self.spiffe_id), serial=self.serial[:12],
              ttl=round(self.not_after - self.not_before))

    def _rotate_loop(self) -> None:
        while not self._stop.is_set():
            lifetime = max(2.0, self.not_after - self.not_before)
            delay = max(1.0, lifetime / 2 - (time.time() - self.not_before - 5))   # rotate at half-life
            if self._stop.wait(delay):
                return
            try:
                self.refresh()
            except IdentityError as exc:
                audit(self.log_name, 'identity', event='rotation_failed', reason=str(exc))
                if self._stop.wait(2.0):
                    return
