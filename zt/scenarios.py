"""Attack simulations and checks. Test-case IDs follow the report (Chapter 5, Sections 5.2 and 5.7-5.8).

Every scenario states the EXPECTED outcome first and then records what was OBSERVED, exactly
like the "Expected result / Observed" columns of the report's test tables.
"""
from __future__ import annotations

import base64
import datetime as dt
import http.client
import json
import ssl
import tempfile
import os
import time
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtensionOID, NameOID

from . import jwtlite
from .ca import attest_token
from .common import (AUDIENCE, CTL_OFFSET, HOST, ISSUER, PORTS, SVID_TTL, http_json, load_registry,
                     read_audit)
from .identity import IdentityError, WorkloadIdentity
from .mesh import mesh_request


@dataclass
class Result:
    tc: str
    title: str
    expected: str
    observed: str
    ok: bool


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b'=').decode()


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + '=' * (-len(text) % 4))


class Lab:
    """Helpers that play the roles of users, attackers and the operator."""

    def __init__(self, stack):
        self.stack = stack
        self.registry = load_registry()
        self._identities = []

    # ---- actors ------------------------------------------------------------------------
    def token(self, sub='alice', roles=('shortener-user',), ttl=300, iss=ISSUER, aud=AUDIENCE) -> str:
        return jwtlite.encode({'iss': iss, 'aud': aud, 'sub': sub, 'roles': list(roles),
                               'exp': time.time() + ttl}, self.stack.jwt_secret)

    def gw(self, method, path, body=None, token=None):
        conn = http.client.HTTPConnection(HOST, PORTS['gateway'], timeout=5)
        try:
            headers = {'Content-Type': 'application/json'}
            if token:
                headers['Authorization'] = 'Bearer ' + token
            conn.request(method, path, body=json.dumps(body) if body is not None else None, headers=headers)
            resp = conn.getresponse()
            raw = resp.read()
            try:
                return resp.status, json.loads(raw) if raw else None
            except ValueError:
                return resp.status, raw.decode(errors='replace')
        finally:
            conn.close()

    def identity(self, workload, token=None) -> WorkloadIdentity:
        ident = WorkloadIdentity(workload, token or attest_token(self.stack.node_secret, workload),
                                 name='harness-' + workload).start()
        self._identities.append(ident)
        return ident

    def close(self) -> None:
        for ident in self._identities:
            ident.stop()

    # ---- observation and operator actions ----------------------------------------------
    def ctl(self, service, action):
        status, data = http_json(PORTS[service] + CTL_OFFSET, 'POST', '/attack?action=' + action, timeout=10)
        return (data or {}).get('outcome', 'HTTP %s' % status)

    def status(self, service) -> dict:
        return http_json(PORTS[service] + CTL_OFFSET, 'GET', '/status')[1]

    def wait_event(self, service, kind, since, timeout=4.0, **match):
        end = time.time() + timeout
        while time.time() < end:
            for ev in read_audit():
                if ev['service'] == service and ev['kind'] == kind and ev['ts'] >= since \
                        and all(ev.get(k) == v for k, v in match.items()):
                    return ev
            time.sleep(0.05)
        return None

    def release(self, service) -> None:
        http_json(PORTS['controlplane'], 'POST', '/release', {'workload': service},
                  headers={'X-Admin-Token': self.stack.admin_token})
        # wait until the service is un-quarantined AND every peer has dropped it from its revocation list
        end = time.time() + 6
        target = self.registry[service]
        while time.time() < end:
            states = [self.status(name) for name in ('db', 'cache', 'api', 'gateway')]
            if not states[['db', 'cache', 'api', 'gateway'].index(service)]['quarantined'] and \
                    all(target not in st['revoked_seen'] for st in states):
                return
            time.sleep(0.1)


def forged_context(spiffe_id: str) -> ssl.SSLContext:
    """A client certificate the attacker made up (self-signed) that CLAIMS to be a real workload."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'forged')])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=1)).not_valid_after(now + dt.timedelta(hours=1))
            .add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(spiffe_id)]), critical=False)
            .sign(key, hashes.SHA256()))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE             # the attacker does not care about the server's identity
    with tempfile.TemporaryDirectory() as tmp:
        c, k = os.path.join(tmp, 'c.pem'), os.path.join(tmp, 'k.pem')
        with open(c, 'wb') as fh:
            fh.write(cert.public_bytes(serialization.Encoding.PEM))
        with open(k, 'wb') as fh:
            fh.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))
        ctx.load_cert_chain(c, k)
    return ctx


def run_all(lab: Lab, say=lambda text: None, show=lambda result: None) -> list:
    results: list = []
    reg = lab.registry
    ttl = lab.stack.ttl

    def add(tc, title, expected, observed, ok):
        result = Result(tc, title, expected, observed, bool(ok))
        results.append(result)
        show(result)

    names = ['db', 'cache', 'api', 'gateway']
    before = {n: lab.status(n) for n in names}
    t_start = time.time()
    att = lab.identity('attacker')               # insider with a VALID identity of the WRONG namespace
    api_replica = lab.identity('api')            # a second replica of the api identity (for protocol tests)

    # ------------------------------------------------------------------------------------
    say('1. Normal operation: the secured application still works')
    token = lab.token()
    status, body = lab.gw('POST', '/shorten', {'original_url': 'https://example.org/report'}, token)
    alias = (body or {}).get('alias', '')
    add('TC-13a', 'Authorized user creates a short URL', 'HTTP 201', 'HTTP %s' % status, status == 201)
    status, body = lab.gw('GET', '/' + alias)
    add('APP-01', 'Anyone can follow a short link (served from cache over mTLS)',
        'HTTP 200, source=cache', 'HTTP %s, source=%s' % (status, (body or {}).get('source')),
        status == 200 and (body or {}).get('source') == 'cache')

    # ------------------------------------------------------------------------------------
    say('2. Workload identity and mutual TLS (research question RQ1)')
    conn = http.client.HTTPConnection(HOST, PORTS['cache'], timeout=3)
    try:
        conn.request('GET', '/kv/probe')
        resp = conn.getresponse()
        add('TC-05', 'Plain-text HTTP to a STRICT mTLS service', 'no HTTP response (connection refused/reset)',
            'HTTP %s returned' % resp.status, False)
    except (http.client.HTTPException, OSError) as exc:
        add('TC-05', 'Plain-text HTTP to a STRICT mTLS service', 'no HTTP response (connection refused/reset)',
            'connection dropped (%s)' % type(exc).__name__, True)
    finally:
        conn.close()

    conn = http.client.HTTPSConnection(HOST, PORTS['cache'], context=forged_context(reg['api']), timeout=3)
    try:
        conn.request('GET', '/kv/probe')
        resp = conn.getresponse()
        add('TC-06', 'Self-signed certificate that claims the API\'s SPIFFE ID', 'TLS handshake rejected',
            'HTTP %s returned' % resp.status, False)
    except (ssl.SSLError, http.client.HTTPException, OSError) as exc:
        add('TC-06', 'Self-signed certificate that claims the API\'s SPIFFE ID', 'TLS handshake rejected',
            'rejected (%s)' % type(exc).__name__, True)
    finally:
        conn.close()

    ctx = api_replica.custom_client_context(min_version=ssl.TLSVersion.TLSv1_2, max_version=ssl.TLSVersion.TLSv1_2)
    conn = http.client.HTTPSConnection(HOST, PORTS['cache'], context=ctx, timeout=3)
    try:
        conn.connect()
        add('TC-07', 'Valid identity but only TLS 1.2 offered', 'handshake fails (TLS 1.3 required)', 'connected', False)
    except (ssl.SSLError, OSError) as exc:
        add('TC-07', 'Valid identity but only TLS 1.2 offered', 'handshake fails (TLS 1.3 required)',
            'handshake failed (%s)' % type(exc).__name__, True)
    finally:
        conn.close()

    conn = http.client.HTTPSConnection(HOST, PORTS['cache'], context=api_replica.client_context, timeout=3)
    conn.connect()
    cert = x509.load_der_x509_certificate(conn.sock.getpeercert(binary_form=True))
    conn.close()
    sans = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value \
        .get_values_for_type(x509.UniformResourceIdentifier)
    bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
    ku = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
    life = (cert.not_valid_after_utc - cert.not_valid_before_utc).total_seconds()
    ok = sans == [reg['cache']] and not bc.ca and ku.digital_signature and not ku.key_cert_sign and life <= ttl + 10
    add('TC-08', 'Served certificate follows the SPIFFE X.509-SVID profile',
        'one URI SAN = cache ID, CA=false, digitalSignature, short lifetime',
        'URI SAN=%s, CA=%s, lifetime=%ds' % (sans[0].split('/sa/')[-1] if sans else '?', bc.ca, life), ok)

    s1, _ = mesh_request(att, 'api', 'GET', '/healthz')
    s2, _ = mesh_request(att, 'cache', 'GET', '/kv/probe')
    add('TC-10', 'Wrong-namespace impersonation (ServiceAccount named fastapi-sa in namespace "attacker")',
        'HTTP 403 from api and cache', 'api: HTTP %s, cache: HTTP %s' % (s1, s2), s1 == 403 and s2 == 403)

    errors = []
    for workload, tok in (('ghost', attest_token(lab.stack.node_secret, 'ghost')), ('api', 'not-the-right-token')):
        try:
            WorkloadIdentity(workload, tok, name='harness-' + workload).start()
            errors.append('%s: certificate issued!' % workload)
        except IdentityError as exc:
            errors.append(str(exc)[:70])
    add('TC-11', 'Unregistered workload / forged attestation token asks for an identity',
        'no certificate is issued', ' | '.join(errors), all('issued' not in e for e in errors))

    s, _ = mesh_request(att, 'db', 'GET', '/urls/' + alias)
    add('TC-19', 'Default deny: a registered identity that no policy lists tries to read the database',
        'HTTP 403', 'HTTP %s' % s, s == 403)

    # ------------------------------------------------------------------------------------
    say('3. End-user tokens and layer-7 authorization at the gateway (research question RQ2)')
    body = {'original_url': 'https://example.org/x'}
    s, _ = lab.gw('POST', '/shorten', body)
    add('TC-14', 'Protected route without any token', 'HTTP 403 (no principal)', 'HTTP %s' % s, s == 403)
    s, _ = lab.gw('POST', '/shorten', body, lab.token(ttl=-30))
    add('TC-15', 'Expired token', 'HTTP 401', 'HTTP %s' % s, s == 401)
    h, p, sig = token.split('.')
    claims = json.loads(_b64d(p))
    claims['roles'] = ['shortener-admin', 'shortener-user']
    tampered = '%s.%s.%s' % (h, _b64e(json.dumps(claims).encode()), sig)
    s, _ = lab.gw('POST', '/shorten', body, tampered)
    add('TC-16', 'Token whose payload was edited (signature no longer matches)', 'HTTP 401', 'HTTP %s' % s, s == 401)
    none_token = '%s.%s.' % (_b64e(json.dumps({'alg': 'none', 'typ': 'JWT'}).encode()), p)
    s, _ = lab.gw('POST', '/shorten', body, none_token)
    add('TC-17', 'Unsigned token with alg=none', 'HTTP 401', 'HTTP %s' % s, s == 401)
    s, _ = lab.gw('POST', '/shorten', body, lab.token(roles=()))
    add('TC-18', 'Valid token without the required role', 'HTTP 403', 'HTTP %s' % s, s == 403)
    s, _ = lab.gw('DELETE', '/shorten', None, token)
    add('TC-13b', 'Forbidden HTTP verb (DELETE) with a valid token', 'HTTP 403', 'HTTP %s' % s, s == 403)
    s, _ = lab.gw('GET', '/internal/stats', None, token)
    add('TC-20', 'Internal API path reached through the gateway', 'HTTP 403 (only the API itself may call it)',
        'HTTP %s' % s, s == 403)

    # ------------------------------------------------------------------------------------
    say('4. Lateral movement from a compromised service (blast-radius containment)')
    o1 = lab.ctl('cache', 'lateral_db')
    o2 = lab.ctl('cache', 'lateral_api')
    add('TC-21', 'Compromised cache (valid identity) tries to reach the database and the API',
        'HTTP 403 for both', 'db: %s, api: %s' % (o1, o2), o1 == 'HTTP 403' and o2 == 'HTTP 403')

    # ------------------------------------------------------------------------------------
    say('5. Automatic identity rotation (functional requirement FR3) - waiting for the certificates to renew')
    deadline = t_start + ttl + 12
    while time.time() < deadline:
        now_state = {n: lab.status(n) for n in names}
        if all(now_state[n]['serial'] != before[n]['serial'] for n in names):
            break
        time.sleep(0.5)
    now_state = {n: lab.status(n) for n in names}
    rotated = [n for n in names if now_state[n]['serial'] != before[n]['serial']]
    same_ids = all(now_state[n]['spiffe_id'] == before[n]['spiffe_id'] for n in names)
    add('TC-09', 'Every service gets a new certificate before the old one expires, without a restart',
        'new serial numbers within the lifetime (%d s), SPIFFE IDs unchanged' % ttl,
        '%d of %d services rotated after %.0f s, identities unchanged: %s' % (len(rotated), len(names), time.time() - t_start, same_ids),
        len(rotated) == len(names) and same_ids)

    # ------------------------------------------------------------------------------------
    say('6. Runtime detection and automatic containment (research question RQ3)')
    t0 = time.time()
    outcome = lab.ctl('cache', 'shell')
    alert = lab.wait_event('cache', 'alert', t0, rule='ZTA Shell Spawned in Microservice Container')
    resp = lab.wait_event('cache', 'response', t0)
    q = lab.status('cache')['quarantined']
    mttd = (alert['ts'] - t0) * 1000 if alert else None
    mttc = (resp['ts'] - alert['ts']) * 1000 if alert and resp else None
    add('TC-26', 'Shell spawned inside the cache process (simulated remote code execution)',
        'CRITICAL alert, then quarantine and identity revocation',
        'alert=%s, quarantined=%s, detect~%s ms, contain~%s ms' % (
            bool(alert), q, 'n/a' if mttd is None else '%.0f' % mttd, 'n/a' if mttc is None else '%.0f' % mttc),
        alert and q and resp)
    lab.release('cache')

    t0 = time.time()
    outcome = lab.ctl('db', 'credential')
    alert = lab.wait_event('db', 'alert', t0, rule='ZTA Credential File Read by Application')
    resp = lab.wait_event('db', 'response', t0)              # containment finished (quarantine + revocation)
    add('TC-28', 'Process reads a (decoy) service-account token file', 'CRITICAL alert, then containment',
        'alert=%s, contained=%s' % (bool(alert), bool(resp)), alert and resp)
    lab.release('db')

    t0 = time.time()
    outcome = lab.ctl('api', 'egress')
    alert = lab.wait_event('api', 'alert', t0, rule='ZTA Unexpected Outbound Connection')
    resp = lab.wait_event('api', 'response', t0)
    add('TC-23', 'Service tries to open a connection to the public internet (192.0.2.10:3333)',
        'connection blocked, CRITICAL alert, containment', '%s; alert=%s, contained=%s' % (outcome, bool(alert), bool(resp)),
        alert and resp and outcome.startswith('blocked'))
    lab.release('api')

    # incident-response story on the API
    s_before, _ = lab.gw('GET', '/' + alias)
    t0 = time.time()
    lab.ctl('api', 'shell')
    lab.wait_event('api', 'response', t0)
    s_during, _ = lab.gw('GET', '/' + alias)
    end, peer = time.time() + 4, ''
    while time.time() < end:                      # peers learn about the revocation within about a second
        peer = lab.ctl('api', 'call_cache')
        if peer == 'HTTP 403':
            break
        time.sleep(0.2)
    add('IR-01', 'API is compromised: legitimate users are protected from it', 'HTTP 200 before, HTTP 503 during',
        'before: %s, during: %s' % (s_before, s_during), s_before == 200 and s_during == 503)
    add('IR-02', 'Peers reject the revoked identity of the compromised API', 'cache answers HTTP 403', peer, peer == 'HTTP 403')
    lab.release('api')
    s_after, _ = lab.gw('GET', '/' + alias)
    add('IR-03', 'Operator releases the workload after investigation', 'service works again (HTTP 200)',
        'HTTP %s' % s_after, s_after == 200)

    lab.close()
    return results
