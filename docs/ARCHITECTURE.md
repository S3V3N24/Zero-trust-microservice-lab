# Architecture

## Components and ports

```text
                       Internet (end user, token in the Authorization header)
                                         |
                              http://127.0.0.1:8000
                      +--------------------------------------+
                      |  GATEWAY  (ingress gateway)          |
                      |  1. validate JWT  (401 if invalid)   |
                      |  2. policy check  (403 if denied)    |
                      +------------------+-------------------+
                                         | mutual TLS 1.3, caller identity = gateway SVID
                      +------------------v-------------------+
                      |  API  :9001   (fastapi-backend)      |   only the gateway may call it
                      +---------+---------------------+------+
              mTLS, identity = api                      | mTLS, identity = api
                      +---------v------+       +--------v---------+
                      |  CACHE  :9002  |       |  DB  :9003       |   only the api may call them,
                      |  (redis-cache) |       |  (postgres-db)   |   only GET/PUT /kv/*, GET/POST /urls*
                      +----------------+       +------------------+

   CONTROL PLANE :9000  certificate authority: attestation, SVID issuance, revocation list
   DASHBOARD     :8080  live view of identities, decisions and alerts
   audit log     runtime/audit.jsonl  (every decision, handshake, alert and identity event)
```

Every service process contains the same "sidecar" logic (`zt/mesh.py`) and a runtime sentinel (`zt/sentinel.py`).

## Life of one request (POST /shorten)

1. The user sends the request with a bearer token to the gateway.
2. The gateway checks the token: algorithm, signature, issuer, audience, expiry. A bad token gives **401**.
3. The gateway evaluates its policy: POST `/shorten` needs a validated user with the role `shortener-user`. Otherwise **403**.
4. The gateway opens a TLS 1.3 connection to the API. Both sides present certificates signed by the CA. The gateway also checks that the
   server's SPIFFE ID is the one registered for the API (`mesh_request`).
5. The API sidecar reads the caller's SPIFFE ID from the certificate, checks it is not revoked, then evaluates the API policy
   (only the gateway identity is allowed).
6. The API calls the database and the cache the same way. Each of them accepts only the API identity and only specific methods and paths.
7. Each decision (allowed or denied, who, what, why) is appended to the audit log and shown on the dashboard.

## Identity lifecycle (report Sections 3.3, 3.8, 3.12)

1. The launcher ("SPIRE agent") starts each process with an attestation token (HMAC of the workload name).
2. The workload generates its own key pair and sends a certificate signing request plus its token to the CA.
3. The CA looks up the **registration entry** (`config/registry.json`) and verifies the token. The CA, not the workload, decides the identity
   and writes it into the certificate (one URI SAN, `CA=false`, `digitalSignature`).
4. The certificate lives for `--ttl` seconds (default 30; the report uses 1 hour). The workload renews it at half-life with a **new key**.
5. The private key is kept in memory. Key files exist only for the milliseconds OpenSSL needs to load them.
6. A workload without a registration entry, or with a wrong token, receives nothing (TC-11).

## Policy evaluation (report Section 2.18)

```text
1. any matching DENY policy                   -> DENY
2. no ALLOW policy applies to this workload   -> ALLOW      ("no policy" is not "deny")
3. any matching ALLOW policy                  -> ALLOW
4. otherwise                                  -> DENY       (default deny)
```

`config/policies.json` begins with `deny-all`, an ALLOW policy with no rules. It matches nothing but makes every workload default-deny
(Theorem 1 of the report). The unit tests in `tests/test_policy.py` check these statements.

## Runtime detection and response (report Sections 4.5, 4.13)

| Rule | Priority | Trigger | Effect |
| --- | --- | --- | --- |
| ZTA Shell Spawned in Microservice Container | CRITICAL | process start of sh, bash, cmd, powershell ... | alert, quarantine, revoke |
| ZTA Credential File Read by Application | CRITICAL | open of a file in `decoy_secrets/` | alert, quarantine, revoke |
| ZTA Unexpected Outbound Connection | CRITICAL | connect() to a non-loopback address | connection **blocked**, alert, quarantine, revoke |
| ZTA Package Manager or Downloader Executed | WARNING | pip, curl, wget, apt ... | alert |

The response of a CRITICAL alert (the report's "contain first" ladder):

1. the service immediately answers every request with **503** (quarantine)
2. it asks the CA to **revoke** its identity, so peers answer **403** to anything it sends
3. the CA refuses to renew its certificate
4. an operator investigates, then runs `python demo.py release <service>`

## Where the prototype differs from the real stack

| Topic | Report (Kubernetes) | Prototype |
| --- | --- | --- |
| Isolation unit | Pods with a sidecar container | Processes with an embedded library |
| Runtime sensor | eBPF system-call tracing in the kernel | Python audit hooks inside the process |
| Network policy | Cilium identity policy in the kernel | Policy engine in the sidecar plus egress block in the sentinel |
| Attestation | Kubelet, cgroups, node attestation | HMAC token from the launcher |
| Policy language | Istio YAML, Rego | JSON with the same evaluation order |
| User tokens | RS256 from Keycloak | HS256 from a stand-in issuer |

These simplifications keep the project runnable on a laptop while preserving the behaviour that the report's tests check.
