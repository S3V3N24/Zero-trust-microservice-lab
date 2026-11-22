# Presentation script (about 10 minutes)

## Before you start

1. `python demo.py --step --open` (or run `python demo.py --step` and open http://127.0.0.1:8080 yourself).
2. Put the terminal and the dashboard side by side. Press Enter once the dashboard shows four healthy workloads.

## 1. The idea (1 minute)

"Traditional security trusts everything inside the network. In Kubernetes, one hacked container then reaches everything.
Zero trust removes that assumption: every call proves who it is, is checked against a policy, and the running code is watched."

Point at the dashboard: four workloads, each with a **certificate that expires in about 30 seconds**. These are short-lived
identities, not IP addresses.

## 2. Walk the sections (6 minutes)

Press Enter for each section and read the *expected* line before the *observed* line.

| Section | What to say |
| --- | --- |
| 1 Normal operation | "The application works. Redirects are served from the cache over mutual TLS." |
| 2 Identity and mTLS | "Plain HTTP is dropped. A self-made certificate that *claims* to be the API is rejected. A real identity from the wrong namespace gets 403. A workload that is not registered cannot get a certificate at all." |
| 3 Gateway | "Five ways to attack the login: no token, expired, edited, unsigned, no role. Each is stopped, and 401 versus 403 shows *which* check stopped it." |
| 4 Lateral movement | "Even a valid, hijacked cache cannot reach the database or the API. The blast radius is one service." |
| 5 Rotation | "While we waited, every certificate was replaced. A stolen key is only useful for seconds." Show serials changing on the dashboard. |
| 6 Runtime | "The attacker runs a shell, reads a credential file, tries to phone home. Each is detected. The service is quarantined, its identity revoked, and the user-facing app answers 503 instead of running attacker-controlled code. After investigation, the operator releases it." |

Show on the dashboard: the red **ALERT** rows, the **QUARANTINED** badge on the card, then the green recovery.

## 3. Live moment (2 minutes, optional)

With `python demo.py up --open` running:

```bash
python demo.py token alice
curl -s -X POST http://127.0.0.1:8000/shorten -H "Authorization: Bearer <token>" \
     -H "Content-Type: application/json" -d '{"original_url":"https://example.org"}'
curl -s -X POST "http://127.0.0.1:11002/attack?action=shell"     # hijack the cache
python demo.py release cache
```

Let the teacher choose which service to "hijack": `cache` (11002), `db` (11003), `api` (11001) or `gateway` (10000).
Actions: `shell`, `credential`, `egress`, `lateral_db`, `lateral_api`, `call_cache`.

## 4. Performance (1 minute)

`python demo.py bench` compares plain HTTP with the secured path. Explain the finding: with connection reuse the overhead is small;
a new TLS handshake for every request costs far more, which is why the real mesh keeps connections open.
Say clearly that these numbers come from this Python prototype and that the Kubernetes numbers are in the report.

## Questions you may get

* **Is this Kubernetes?** No. It is a runnable model of the same architecture. The report documents the Kubernetes deployment
  (Istio, SPIRE, OPA, Cilium, Falco) with the same test cases.
* **What is simulated?** Attestation (HMAC token instead of kubelet checks), the sensor (Python audit hooks instead of eBPF), the user
  tokens (HS256 instead of Keycloak). See "Honest scope" in the README.
* **Why does the cache or db "fail" after the attack?** That is the containment: the quarantined service stops answering until an
  operator releases it. Availability is traded for safety, as in the report's fail-closed design.
* **Why 30-second certificates?** So rotation is visible in a demo. The report uses one hour; the trade-off is analysed in Section 2.14.
* **How do you know the tests can fail?** Disable a control and the matching tests turn red (for example, set the server's
  `verify_mode` to `CERT_NONE` in `zt/identity.py` and TC-06 fails).
