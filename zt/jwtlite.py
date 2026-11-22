"""Minimal HS256 JSON Web Token implementation (stand-in for Keycloak / OIDC).

The report uses RS256 tokens issued by an identity provider and validated by Istio's
RequestAuthentication. This module reproduces the same *checks* (algorithm, signature,
issuer, audience, expiry) with the standard library only.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time


class JWTError(Exception):
    """Raised when a token must be rejected (the gateway maps this to HTTP 401)."""


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b'=').decode()


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + '=' * (-len(text) % 4))


def encode(payload: dict, secret: str) -> str:
    header = _b64e(json.dumps({'alg': 'HS256', 'typ': 'JWT'}).encode())
    body = _b64e(json.dumps(payload).encode())
    sig = hmac.new(secret.encode(), f'{header}.{body}'.encode(), hashlib.sha256).digest()
    return f'{header}.{body}.{_b64e(sig)}'


def verify(token: str, secret: str, issuer: str, audience: str, now: float | None = None) -> dict:
    parts = token.split('.')
    if len(parts) != 3:
        raise JWTError('malformed token')
    try:
        header = json.loads(_b64d(parts[0]))
        claims = json.loads(_b64d(parts[1]))
    except Exception:
        raise JWTError('malformed token')
    if header.get('alg') != 'HS256':          # rejects alg=none and algorithm confusion
        raise JWTError('algorithm not allowed: %r' % header.get('alg'))
    expected = hmac.new(secret.encode(), f'{parts[0]}.{parts[1]}'.encode(), hashlib.sha256).digest()
    try:
        given = _b64d(parts[2])
    except Exception:
        raise JWTError('malformed signature')
    if not hmac.compare_digest(expected, given):
        raise JWTError('signature verification failed')
    if claims.get('iss') != issuer:
        raise JWTError('wrong issuer')
    aud = claims.get('aud')
    if audience not in (aud if isinstance(aud, list) else [aud]):
        raise JWTError('wrong audience')
    if float(claims.get('exp', 0)) < (now if now is not None else time.time()):
        raise JWTError('token is expired')
    return claims
