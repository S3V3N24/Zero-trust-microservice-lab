"""Public entry point (report: Istio ingress gateway).

Terminates the *end-user* side: validates the JWT (RequestAuthentication), applies the gateway
policy (AuthorizationPolicy) and forwards allowed requests to the API over mutual TLS.
HTTP 401 = a token was presented but is invalid; HTTP 403 = no (sufficient) credentials.
"""
import os

from ..common import AUDIENCE, ISSUER, audit
from ..jwtlite import JWTError, verify
from ..mesh import MeshError, MeshService


class GatewayApp:
    name = 'gateway'
    tls = False                     # user-facing side is plain HTTP on localhost for the demo

    def __init__(self):
        self.secret = os.environ['ZT_JWT_SECRET']

    def authenticate(self, svc, req, headers):
        auth = headers.get('Authorization')
        if not auth:
            return None             # anonymous: allowed only where the policy permits
        if not auth.startswith('Bearer '):
            return 401, {'error': 'malformed Authorization header'}
        try:
            claims = verify(auth[7:], self.secret, ISSUER, AUDIENCE)
        except JWTError as exc:
            audit(svc.name, 'authn', ok=False, reason=str(exc), method=req.method, path=req.path)
            svc.count('denied')
            return 401, {'error': 'Jwt verification fails', 'reason': str(exc)}
        req.user = '%s/%s' % (claims['iss'], claims.get('sub', '?'))
        req.roles = tuple(claims.get('roles', []))
        return None

    def handle(self, svc, req, body, headers, raw_path):
        forward = {'Authorization': headers['Authorization']} if headers.get('Authorization') else {}
        try:
            return svc.call('api', req.method, raw_path, body or None, forward)
        except (MeshError, OSError) as exc:
            return 502, {'error': 'upstream unavailable', 'detail': str(exc)[:120]}


if __name__ == '__main__':
    MeshService(GatewayApp()).run()
