# Zero-Trust Microservices Lab

A small, runnable prototype of the **Zero-Trust Architecture for Cloud-Native Microservices** described in the project report
(NIST SP 800-207: *never trust, always verify*). It runs on any computer with Python. No Docker or Kubernetes is needed.

A URL-shortener application (gateway, API, cache, database) is protected by the same layers as the report:

| Layer | What it does here |
| --- | --- |
| **Workload identity** | A mini certificate authority issues short-lived, SPIFFE-style X.509 identities and rotates them automatically |
| **Mutual TLS 1.3** | Every service-to-service call is encrypted and both sides prove who they are |
| **Authorization policy** | Istio-style rules: default deny, per-identity allow lists, HTTP method and path rules |
| **End-user tokens** | The gateway validates JWTs (signature, issuer, audience, expiry, role) |
| **Runtime detection** | A Falco-style sentinel spots a shell, credential-file read or outbound connection inside a service |
| **Automatic response** | A compromised service is quarantined and its identity revoked; peers stop trusting it |

## Quick start

Requires Python 3.9 or newer (tested on 3.12) and one package.

```bash
git clone https://github.com/<your-username>/zta-microservices-demo.git
cd zta-microservices-demo
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python demo.py
```

`python demo.py` starts everything, runs 24 attack and verification scenarios (about 20 seconds), prints expected versus observed
for each, writes `runtime/report.md` and shuts down. While it runs, open the live dashboard at **http://127.0.0.1:8080**.

## Commands

```text
python demo.py                 guided demo: start, attack, verify, stop
python demo.py --step          same, pausing before each section (good for presenting)
python demo.py up              start the system and keep it running (dashboard + gateway)
python demo.py bench           latency of plain HTTP versus the zero-trust path
python demo.py test            quiet run for CI; exit code 1 if any check fails
python demo.py token alice     print a user JWT for curl (while "up" is running)
python demo.py release api     release a quarantined service (while "up" is running)
python -m unittest discover -s tests -v     unit and integration tests
```

Try it by hand while `python demo.py up` is running:

```bash
TOKEN=$(python demo.py token alice)
curl -s -X POST http://127.0.0.1:8000/shorten -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" -d '{"original_url":"https://example.org"}'
curl -s http://127.0.0.1:8000/<alias>                              # public redirect
curl -s -X POST http://127.0.0.1:8000/shorten -d '{}'              # no token -> 403
curl -s -X POST "http://127.0.0.1:11002/attack?action=shell"       # simulate a hijacked cache, watch the dashboard
python demo.py release cache                                       # operator releases it
```

## What the demo proves

Test IDs match the report (Chapter 5). Each line states the expected result, then records what actually happened.

| Section | Checks |
| --- | --- |
| Normal operation | TC-13a create a URL, APP-01 follow a link served from the cache over mTLS |
| Identity and mTLS | TC-05 plain HTTP refused, TC-06 forged certificate refused, TC-07 TLS 1.2 refused, TC-08 certificate matches the SPIFFE profile, TC-10 wrong-namespace impersonation, TC-11 unregistered workload gets no identity, TC-19 default deny |
| Gateway authorization | TC-14 no token, TC-15 expired, TC-16 tampered, TC-17 alg=none, TC-18 missing role, TC-13b forbidden verb, TC-20 internal path |
| Lateral movement | TC-21 a hijacked cache cannot reach the database or the API |
| Rotation | TC-09 every certificate is replaced before it expires, without a restart |
| Runtime and response | TC-26 shell, TC-28 credential read, TC-23 outbound connection blocked, IR-01..03 quarantine, revocation and recovery |

## How it maps to the report

| Report component | In this prototype |
| --- | --- |
| SPIRE server (CA, attestation, SVIDs) | `zt/ca.py`, `zt/controlplane.py` |
| SPIRE agent / Envoy SDS (rotation at half-life) | `zt/identity.py` |
| Envoy sidecar (mTLS, AuthorizationPolicy) | `zt/mesh.py`, `zt/policy.py`, `config/policies.json` |
| Istio ingress gateway, RequestAuthentication | `zt/services/gateway.py`, `zt/jwtlite.py` |
| Falco (eBPF) and Falcosidekick response | `zt/sentinel.py`, `MeshService._on_critical` in `zt/mesh.py` |
| FastAPI, Redis, PostgreSQL | `zt/services/api.py`, `cache.py`, `db.py` (in-memory store, SQLite) |
| Prometheus, Hubble, Grafana | `runtime/audit.jsonl` and `zt/dashboard.html` |
| fortio benchmark | `zt/bench.py` |

More detail: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). Presenting it: [docs/DEMO_SCRIPT.md](docs/DEMO_SCRIPT.md). Example results: [docs/sample-report.md](docs/sample-report.md).

## Honest scope: what this is and is not

* It is a **prototype of the architecture**, not the Kubernetes deployment. Services are processes on one machine and the "sidecar" is a
  library inside each process.
* Attestation is an HMAC token from the launcher (SPIRE verifies kubelet and kernel facts). JWTs use HS256 (Keycloak would use RS256).
  Policies are JSON in Istio's evaluation order (the report uses Istio YAML and Rego).
* The sentinel uses Python audit hooks, not kernel eBPF, so it only sees events inside the service process.
* Benchmark numbers come from this Python prototype and are **not** measurements of the Kubernetes testbed. Do not mix them in the report's
  Section 5.3 tables.
* The per-service `/attack` endpoints are a demo-only compromise simulator. They run a fixed whitelist of harmless actions, listen on
  127.0.0.1 only, and must never be exposed.

## Troubleshooting

* **Ports already in use** - stop the other run, or shift every port: `ZT_PORT_OFFSET=100 python demo.py` (Windows PowerShell: `$env:ZT_PORT_OFFSET=100`).
* **"no TLS 1.3 support"** - install a current Python from python.org or Homebrew (the macOS system Python is too old).
* **A check fails on a very slow computer** - raise the certificate lifetime: `python demo.py --ttl 60`.
* Service logs are in `runtime/logs/`.

Tested on Python 3.12 (Linux). Windows and macOS are expected to work but were not tested.

## License

MIT, see `LICENSE`.
