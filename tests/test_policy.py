"""Unit tests for the policy engine and the JWT checks. They mirror the statements of the report, Section 2.18."""
import time
import unittest

import _env  # noqa: F401  (must be first)

from zt import jwtlite
from zt.policy import Request, decide, load_policies

FASTAPI = 'spiffe://cluster.local/ns/url-shortener/sa/fastapi-sa'
OTHER = 'spiffe://cluster.local/ns/attacker/sa/fastapi-sa'


def req(principal=FASTAPI, method='GET', path='/x', user=None, roles=()):
    return Request(principal=principal, method=method, path=path, user=user, roles=tuple(roles))


class PolicyEngine(unittest.TestCase):
    def test_no_policy_allows_all(self):                    # "absence of policy is not denial"
        self.assertTrue(decide('svc', req(), []).allowed)

    def test_empty_allow_policy_denies_all(self):           # Theorem 1: default-deny closure
        deny_all = {'name': 'deny-all', 'selector': '*', 'action': 'ALLOW', 'rules': []}
        self.assertFalse(decide('svc', req(), [deny_all]).allowed)

    def test_allow_list_matches_only_listed_principal(self):
        allow = {'name': 'a', 'selector': 'svc', 'action': 'ALLOW', 'rules': [{'principals': [FASTAPI]}]}
        self.assertTrue(decide('svc', req(FASTAPI), [allow]).allowed)
        self.assertFalse(decide('svc', req(OTHER), [allow]).allowed)

    def test_deny_overrides_allow(self):
        allow = {'name': 'a', 'selector': 'svc', 'action': 'ALLOW', 'rules': [{'principals': [FASTAPI]}]}
        deny = {'name': 'd', 'selector': 'svc', 'action': 'DENY', 'rules': [{'methods': ['DELETE']}]}
        self.assertTrue(decide('svc', req(method='GET'), [allow, deny]).allowed)
        self.assertFalse(decide('svc', req(method='DELETE'), [allow, deny]).allowed)

    def test_adding_a_deny_policy_never_widens_access(self):   # Theorem 2 (monotonicity)
        allow = {'name': 'a', 'selector': 'svc', 'action': 'ALLOW', 'rules': [{}]}
        deny = {'name': 'd', 'selector': 'svc', 'action': 'DENY', 'rules': [{'paths': ['/secret/*']}]}
        for path in ('/', '/secret/1', '/public'):
            before = decide('svc', req(path=path), [allow]).allowed
            after = decide('svc', req(path=path), [allow, deny]).allowed
            self.assertTrue(before or not after)

    def test_selector_limits_policy_to_one_workload(self):
        allow = {'name': 'a', 'selector': 'other', 'action': 'ALLOW', 'rules': [{}]}
        self.assertTrue(decide('svc', req(), [allow]).allowed)    # no ALLOW policy applies to 'svc' -> open

    def test_path_wildcards_and_roles(self):
        policy = {'name': 'p', 'selector': 'svc', 'action': 'ALLOW',
                  'rules': [{'paths': ['/api/*'], 'roles': ['admin'], 'require_user': True}]}
        self.assertTrue(decide('svc', req(path='/api/x', user='u', roles=['admin']), [policy]).allowed)
        self.assertFalse(decide('svc', req(path='/api/x', user='u', roles=['viewer']), [policy]).allowed)
        self.assertFalse(decide('svc', req(path='/other', user='u', roles=['admin']), [policy]).allowed)


class ShippedPolicies(unittest.TestCase):
    """The real policy file must give the call graph of the report: gateway -> api -> cache/db, nothing else."""
    policies = load_policies()
    GATEWAY = 'spiffe://cluster.local/ns/istio-system/sa/istio-ingressgateway-service-account'

    def test_only_gateway_reaches_api(self):
        self.assertTrue(decide('api', req(self.GATEWAY, path='/healthz'), self.policies).allowed)
        self.assertFalse(decide('api', req(OTHER, path='/healthz'), self.policies).allowed)

    def test_only_api_reaches_cache_and_db(self):
        self.assertTrue(decide('cache', req(FASTAPI, path='/kv/a'), self.policies).allowed)
        self.assertTrue(decide('db', req(FASTAPI, path='/urls/a'), self.policies).allowed)
        self.assertFalse(decide('db', req(self.GATEWAY, path='/urls/a'), self.policies).allowed)
        self.assertFalse(decide('db', req(FASTAPI, path='/dump'), self.policies).allowed)

    def test_gateway_rules(self):
        g = lambda **kw: decide('gateway', req(None, **kw), self.policies).allowed
        self.assertTrue(g(method='GET', path='/abc'))
        self.assertFalse(g(method='POST', path='/shorten'))
        self.assertTrue(g(method='POST', path='/shorten', user='u', roles=['shortener-user']))
        self.assertFalse(g(method='POST', path='/shorten', user='u', roles=[]))
        self.assertFalse(g(method='DELETE', path='/shorten', user='u', roles=['shortener-user']))


class JwtChecks(unittest.TestCase):
    SECRET, ISS, AUD = 's3cret', 'https://issuer', 'my-api'

    def mint(self, **over):
        claims = {'iss': self.ISS, 'aud': self.AUD, 'sub': 'alice', 'exp': time.time() + 60}
        claims.update(over)
        return jwtlite.encode(claims, self.SECRET)

    def check(self, token):
        return jwtlite.verify(token, self.SECRET, self.ISS, self.AUD)

    def test_valid_token(self):
        self.assertEqual(self.check(self.mint())['sub'], 'alice')

    def test_rejections(self):
        bad = {
            'expired': self.mint(exp=time.time() - 5),
            'wrong issuer': self.mint(iss='https://evil'),
            'wrong audience': self.mint(aud='other-api'),
            'garbage': 'not.a.token',
            'two parts': 'a.b',
        }
        for name, token in bad.items():
            with self.subTest(name), self.assertRaises(jwtlite.JWTError):
                self.check(token)

    def test_tampered_payload_and_wrong_key(self):
        h, p, s = self.mint().split('.')
        with self.assertRaises(jwtlite.JWTError):
            self.check('%s.%s.%s' % (h, jwtlite._b64e(b'{"iss":"https://issuer","aud":"my-api","exp":9999999999}'), s))
        with self.assertRaises(jwtlite.JWTError):
            jwtlite.verify(self.mint(), 'another-secret', self.ISS, self.AUD)

    def test_alg_none_is_refused(self):
        h = jwtlite._b64e(b'{"alg":"none","typ":"JWT"}')
        p = self.mint().split('.')[1]
        with self.assertRaises(jwtlite.JWTError):
            self.check('%s.%s.' % (h, p))


if __name__ == '__main__':
    unittest.main()
