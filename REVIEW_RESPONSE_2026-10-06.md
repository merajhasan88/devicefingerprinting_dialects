# Response to the joint review of 2026-10-05 and the attestation proposal of 2026-10-06

Covers the Flutter/server repository only; the .NET SDK answers for its own items. `DESIGN.md` §66
holds the full record, `HANDOFF_TO_DOTNET_2026-09-30.md` §8 the items passed to the .NET session.

**Method.** All 20 of your observations reproduced on `7e11403` before any change. Each repair below
was checked against every report stored on the test server before it shipped, and your observations
were re-run against the result.

## Attestation proposal — declined by the owner

Worked through with the owner (DESIGN.md 66.1): local verification of Android key-attestation chains
would prove where the installation key lives and the boot state the bootloader reported, but a
compromised app or OS still signs with the genuine key, the app identity in the certificate comes from
Android, and an exploit-based root leaves the bootloader locked. The owner's decision: no attestation
of any kind, local chain verification included; Remote Key Provisioning is not banned but nothing
relies on it. Phone signals stay untrusted evidence, scored by the server's own logic with velocity
and fraud signals. Recorded with it, and now in `INTEGRATION_GUIDE.md`: without attestation a fully
synthetic client looks like a genuine phone, so farm detection needs velocity on signals a client
cannot mint for free (source network, service-wide creation rate, behaviour, business data) — the
device-level counts key on keys and hints a farm can regenerate.

## Joint review findings

| ID | Disposition | Commit |
|---|---|---|
| R1 runtime growth | **Open, owner decision.** Your recommendation (per-release session profiles, expected growth advisory, developer options + ADB not adding up to a refusal) is recorded in §66.3. Unchanged: a warm .NET session on a developer phone reads 33 / elevated. | — |
| R2 .NET scanner coverage | .NET SDK; passed on. | handoff §8 |
| R3 empty scans | **Fixed.** `checked=true` with zero bytes compared in a bucket that always holds code (Android core/ext/app; iOS app only) is incomplete (+30). Your two zero-coverage observations now score 30 / elevated. Stored reports: none affected. | `fad5c20` |
| R4 hint propagation | **Fixed 2026-10-07, your direction** (§68): a block spreads only from the device's established installations — the original, or a hint-linked one confirmed when an account first linked through an established installation signs in on it. Evidence and links are all kept; account counts unchanged by the owner's decision, with a support-team procedure in the guide. Never stricter than before for any installation; on every stored installation the pick is unchanged. | `ba63ecd` (guide), `1b7d3c5` |
| R5 challenge eviction | **Fixed differently than suggested:** challenges are stateless until used (server-MACed payload, recorded only on consumption, primary key = single use), so a flood has nothing to fill or displace — no new key proof before issuance was needed, and no client changed. The cap and the per-installation budget are gone. A challenge the server did not issue now answers 401 `challenge_payload_mismatch` (was 404 `challenge_not_found`); no client branches on that code. | `5adbab7` |
| R6 .NET command deadline | .NET SDK; passed on. | handoff §8 |
| R7 refresh concurrency | **Server half fixed:** the challenge step no longer revokes; reuse is judged after the key signs. Client half passed to .NET. | `b8ec78a` |
| R8 truncated size classes | **Fixed:** the allowance needs a list covering every mapping and byte; your truncation observation now scores 60 / review. All 60 stored W^X reports are complete lists. | `56ec6d8` |

**Gates at this commit.** `tools/check_security_regressions.py` 34/34 (new: empty scans, challenge
flood and MAC binding, key-less refresh reuse, truncated classes). Conformance suite on PostgreSQL 16.15
(60 checks): 55 passed, 5 skipped in observe; the three enforce-mode checks 3/3. Not run this round:
handsets (no client code changed; the suite's client exercised the new challenge path on PostgreSQL)
and SQL Server — in particular the new challenge path's single-use INSERT there is translation-checked
only, not proven.

**Added 2026-10-07 (R4).** Gate 39/39 (five new checks run the server's own SQL on SQLite, including a
500-device differential against the old device-wide query; four deliberately broken servers each
failed it). Migration 009 on PostgreSQL 16.15: 0 of 4,228 stored installations changed their memory
pick. Suite (63 checks): 58 passed, 0 failed, 5 skipped in observe; the enforce-mode and R4 checks 6/6
in enforce. SQL Server: the new statements are translation-checked only.

