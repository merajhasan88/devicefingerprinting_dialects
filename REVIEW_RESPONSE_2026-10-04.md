# Response to the critical review of 2026-09-29

The review covered the snapshot at `3aafa6c` (server code identical to `4d045eb`). This is what was
done with each finding, as of `main` on 2026-10-04. `DESIGN.md` §63 holds the full record (method,
results and the reasoning behind each decision), §63.3a the owner's decisions, §64 an open question for
you, and `INTEGRATION_GUIDE.md` the customer-facing configuration guide that the review asked for.

**Method.** Every one of the review's 17 observations was reproduced on `4d045eb` with your harness, and
the native harness on a Linux host, before anything changed. Before tightening any evidence rule, all
4,648 integrity reports stored on the test server in September were re-scored offline: none is refused
or newly penalised. Your harness, with every vulnerable-behaviour assertion inverted and its controls
kept, is `tools/check_security_regressions.py` (31 checks; against the reviewed code the first 24 of
them gave 3 passed — the controls — and 21 failed). Your native harness, inverted, is
`tools/native/check_code_integrity.cpp`.

| ID | Disposition | Commits |
|---|---|---|
| F1 step-up intent | **Fixed.** Step-up proof v2 signs token hash, method, path, query, body hash, factor, nonce, timestamp, `purpose`; every request field compared; v1 refused. Stored key factor must match policy; the installation key cannot be its own step-up key; `stepup_key_auth` required. | `d518cae` |
| F2 evidence | **Fixed.** Typed probe fields (malformed → 400); `ok` without its measurements, or `checked:false`, scores like a failed probe (+30); collector version bounded; iOS `code_integrity` required when scored; W^X allowance only for a consistent shape; `required` hardware backing unsatisfied by an absent claim. | `d0414af` `ff44975` `9cb690e` `d2ec2f7` |
| F3 policy failure | **Fixed.** Validated policy snapshot, fails closed (503) after a bounded stale window; readiness 503 `not_ready` with named problems. | `54ba568` |
| F4 coverage | **Fixed.** Any differing byte counts; the scanner compares every target mapping in full and reports expected/compared/skipped/unreadable per bucket; the server checks the figures add up. Partial coverage is visible but report-only — owner decision until fleet data exists. | `1deffe7` `6e846eb` `ae35dba` |
| F5 permissions | **Fixed.** Targets selected before `mprotect`; exact original protection restored by a guard on every path, failures counted. | `6e846eb` |
| F6 hint poisoning | **Partly.** Registrations that never proved their key no longer count toward a device (schema 8, `verified_at`). The "count only once account-bound" half was **not** done: it would let a reinstalling device farm and a never-logged-in compromised install escape, while an attacker can still open an account. The remaining case needs the victim's hint plus a proven key — a recorded limit. | `940b37e` |
| F7 metadata | **Fixed.** Public re-registration no longer changes stored key-security metadata. | `1232166` |
| F8 transport | **Fixed.** Forwarded headers trusted only from `TRUSTED_PROXY_COUNT` proxies; 256 KiB body limit; release clients HTTPS-only. | `1162afc` `c1b0e8d` |
| F9 admission | **Fixed as far as the server goes.** Per-source and per-handle budgets (opt-in with Redis, fail open); a challenge flood drops the oldest unused challenge instead of locking the client out; housekeeping off the request path. No new index without measured plans. | `3ee520d` |
| F10 races | **Fixed** for the first link (savepoint); proven live on PostgreSQL with `tools/race_first_link.py` (reviewed code: `InFailedSqlTransaction`; this build commits). SQL Server and the other interleavings: not yet run. | `6e139f2` `55df912` |
| F11 recovery | **Fixed** for elevated integrity: a step-up proof for the request satisfies it; where none can be accepted (login, registration, refresh) the code now says a clean scan is needed. **Links are never retired** — owner decision: relationship history is the product's evidence; a customer who judges an account legitimate records that in its own systems (guide §5). | `16a2a7a` |
| Query binding | **Fixed.** Access proof v2 signs the query string; v1 configurable for a transition (now over: the test stack is v2-only). | `5f02cac` |
| Subprocess hangs | **Fixed.** 3 s deadline per command. | `e24cae2` |
| Revocation, root secret, release signing | **Owner decision:** customer-owned. The guide states what the root secret derives, that changing it today orphans stored hints and handle lookups, and which certificate to pin under Play App Signing. | `8a837d0` |
| W^X baseline per build | **Open, for you:** §64 sets out a per-app allowance and automated per-build pins; the owner has adopted neither. | — |
| File split / SDK boundaries | **Not done.** | — |

**Found on hardware while validating** (both fixed): an Android 9 step-up alias that had lost its
private key surfaced as an unexplained error (`b74ff1e`); and the client offered step-up for a key the
server had never bound (`215768b`).

**Results at `main` (2026-10-04).** Gate 31/31; native host test 12/12; conformance suite on PostgreSQL
16.15, 59 checks: 54 passed, 5 skipped in observe, and the three enforce-mode checks 3/3 with enforce
briefly on. OPPO (Android 9) and iPhone 7 (iOS 15.8.5, TrollStore) release builds with the server
refusing v1: register, scan, refresh and step-up v2 verified; OPPO 18/trusted with every code-integrity
bucket complete (28 MB compared in about 440 ms), iPhone 0/trusted. The .NET SDK reports its own suite
at 34/34 against the same v2-only server. Not yet re-run: SQL Server.

**Test stack state.** EC2 test server on this `main`, PostgreSQL 16.15 at schema 8, `INTEGRITY_MODE` and
`DEVICE_POLICY_MODE` observe, v2-only access proofs, `TRUSTED_PROXY_COUNT=1`, three W^X build pins, step-up
gated on `/v1/account/sensitive-echo` for the remaining phone runs.
