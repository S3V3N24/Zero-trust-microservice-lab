"""Authorization policy engine with the same evaluation order as Istio (report, Section 2.18).

    1. any matching DENY policy                 -> DENY
    2. no ALLOW policy applies to the workload  -> ALLOW   ("no policy" is NOT "deny")
    3. any matching ALLOW policy                -> ALLOW
    4. otherwise                                -> DENY    (default deny)

An ALLOW policy with an empty rule list matches nothing but still makes the set of ALLOW
policies non-empty, so it turns a workload into default-deny.
"""
from __future__ import annotations

import fnmatch
import json
from dataclasses import dataclass, field

from .common import CONFIG_DIR


@dataclass
class Request:
    principal: str | None            # SPIFFE ID of the calling workload (from the mTLS certificate)
    method: str
    path: str
    user: str | None = None          # "issuer/subject" of a validated end-user JWT
    roles: tuple = field(default_factory=tuple)


@dataclass
class Decision:
    allowed: bool
    reason: str
    policy: str | None = None


def _any_match(patterns, value: str) -> bool:
    return any(fnmatch.fnmatchcase(value, p) for p in patterns)


def rule_matches(rule: dict, req: Request) -> bool:
    if 'principals' in rule and req.principal not in rule['principals']:
        return False
    if 'not_principals' in rule and req.principal in rule['not_principals']:
        return False
    if 'methods' in rule and req.method not in rule['methods']:
        return False
    if 'paths' in rule and not _any_match(rule['paths'], req.path):
        return False
    if 'not_paths' in rule and _any_match(rule['not_paths'], req.path):
        return False
    if rule.get('require_user') and not req.user:
        return False
    if 'roles' in rule and not (set(rule['roles']) & set(req.roles)):
        return False
    return True


def policy_matches(policy: dict, req: Request) -> bool:
    return any(rule_matches(rule, req) for rule in policy.get('rules', []))


def decide(workload: str, req: Request, policies: list) -> Decision:
    applicable = [p for p in policies if p.get('selector', '*') in ('*', workload)]
    for p in (p for p in applicable if p['action'] == 'DENY'):
        if policy_matches(p, req):
            return Decision(False, "denied by DENY policy '%s'" % p['name'], p['name'])
    allow = [p for p in applicable if p['action'] == 'ALLOW']
    if not allow:
        return Decision(True, 'no ALLOW policy applies (open)', None)
    for p in allow:
        if policy_matches(p, req):
            return Decision(True, "allowed by policy '%s'" % p['name'], p['name'])
    return Decision(False, 'no ALLOW policy matched (default deny)', None)


def load_policies() -> list:
    return json.loads((CONFIG_DIR / 'policies.json').read_text(encoding='utf-8'))['policies']
