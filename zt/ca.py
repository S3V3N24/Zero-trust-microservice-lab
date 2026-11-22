"""A miniature SPIFFE/SPIRE-style certificate authority (report Sections 2.4, 3.3, 3.8, 3.11).

What it reproduces from the report
  * identities are bound to *registered workloads*, not to IP addresses
  * attestation: a workload must prove who it is before it receives a certificate
  * X.509-SVIDs: one URI SAN holding the SPIFFE ID, CA=false, digitalSignature, short lifetime
  * the CA chooses the identity; the workload only supplies a public key (CSR)
  * revocation list used for incident response (quarantine of a compromised workload)

What it simplifies: attestation is an HMAC token handed to each process by the launcher,
standing in for the SPIRE agent's kubelet/cgroup checks.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import threading

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


class AttestationError(Exception):
    pass


def attest_token(node_secret: str, workload: str) -> str:
    """The token the launcher ("SPIRE agent") hands to one specific workload process."""
    return hmac.new(node_secret.encode(), workload.encode(), hashlib.sha256).hexdigest()


def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


class CertificateAuthority:
    def __init__(self, entries: dict, node_secret: str, ttl: int):
        self.entries = entries                  # workload -> spiffe id
        self.node_secret = node_secret
        self.ttl = ttl
        self.revoked: dict = {}                 # spiffe id -> reason
        self._lock = threading.Lock()
        self._key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'zta-demo'),
            x509.NameAttribute(NameOID.COMMON_NAME, 'ZTA Demo Root CA (cluster.local)'),
        ])
        now = _utcnow()
        self.root = (
            x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(self._key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=1))
            .not_valid_after(now + dt.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(self._key.public_key()), critical=False)
            .sign(self._key, hashes.SHA256())
        )
        self.bundle_pem = self.root.public_bytes(serialization.Encoding.PEM).decode()

    # ---- attestation -------------------------------------------------------------------
    def attest(self, workload: str, token: str) -> str:
        if workload not in self.entries:
            raise AttestationError('no registration entry for workload %r' % workload)
        expected = attest_token(self.node_secret, workload)
        if not hmac.compare_digest(expected, token or ''):
            raise AttestationError('attestation failed for workload %r' % workload)
        spiffe_id = self.entries[workload]
        if spiffe_id in self.revoked:
            raise AttestationError('identity %s is revoked: %s' % (spiffe_id, self.revoked[spiffe_id]))
        return spiffe_id

    # ---- issuance ----------------------------------------------------------------------
    def issue(self, workload: str, token: str, csr_pem: str) -> dict:
        spiffe_id = self.attest(workload, token)
        csr = x509.load_pem_x509_csr(csr_pem.encode())
        if not csr.is_signature_valid:
            raise AttestationError('invalid CSR signature')
        public_key = csr.public_key()
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            raise AttestationError('only EC keys are accepted')
        now = _utcnow()
        not_after = now + dt.timedelta(seconds=self.ttl)
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, workload)]))
            .issuer_name(self.root.subject)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(seconds=5))     # small clock-skew allowance
            .not_valid_after(not_after)
            # SVID profile: exactly one URI SAN (the SPIFFE ID), leaf certificate, digitalSignature only
            .add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(spiffe_id)]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True, key_cert_sign=False, crl_sign=False, content_commitment=False,
                key_encipherment=False, data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self._key.public_key()), critical=False)
            .sign(self._key, hashes.SHA256())
        )
        return {
            'cert': cert.public_bytes(serialization.Encoding.PEM).decode(),
            'bundle': self.bundle_pem,
            'spiffe_id': spiffe_id,
            'serial': format(cert.serial_number, 'x'),
            'not_before': cert.not_valid_before_utc.timestamp(),
            'not_after': cert.not_valid_after_utc.timestamp(),
        }

    # ---- revocation (incident response) ------------------------------------------------
    def revoke(self, spiffe_id: str, reason: str) -> None:
        with self._lock:
            self.revoked[spiffe_id] = reason

    def release(self, spiffe_id: str) -> bool:
        with self._lock:
            return self.revoked.pop(spiffe_id, None) is not None

    def revoked_ids(self) -> list:
        with self._lock:
            return sorted(self.revoked)
