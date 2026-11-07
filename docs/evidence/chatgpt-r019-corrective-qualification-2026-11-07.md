# R019 — Corrected four-platform static recovery and qualification

**Purpose:** durable exact-head readback after independent static-sensor corrective actions. Retain R018 as historical comparator with a known Linux ARM64 coverage gap and macOS Codex wrapper mis-selection.

## Native source and artifact provenance

| Workcell | Current exact-head GitHub Actions receipt | Original donor status | Derived artifact ZIP SHA256 |
|---|---|---|---|
| Windows x64/ARM64 | [CDR #42315312266](https://github.com/SemperSupra/connected-device-recovery/actions/runs/42315312266), source head `98b7de5922ae442ea7152419e8dbe4b89877af95` | Authenticode Valid; static only | x64 `2755d191e9e09868c15f47c37017963388001f9bfe2327fc660f6c42425466f5`; ARM64 `30e02a9e5d200ed71e48df1b9d8685e3e8f99abb39cb0d93f707a939bdecfa3d` |
| Linux DEB/RPM x64+ARM64 | [CDR #42318105129](https://github.com/SemperSupra/connected-device-recovery/actions/runs/42318105129), source head `c6ae89cdc50ac4449a25d9edb4ed0bf76dd8d91d`, artifact 13550824795 | Derived static only; RPM key unavailable, DEB signer identity not independently proven | `2ce44d45aefc85ba2d91508f62ea323feefdd99ad1e86af44e3120493c87f41e` |
| macOS Classic + unified x64/ARM64 | [CDR #42317919989](https://github.com/SemperSupra/connected-device-recovery/actions/runs/42317919989), source head `d5f1085e02dddc2a90b401c93cabab288e598c33`, artifact 13551383902 | Signed/accepted original app static census, no original process launched | `0fd96b0fe80032dcb4a4b97e25c91e3948ea6cabacda804389b4d3ad1c887b2e` |
| Android APKPure archive | [AAR #42315395444](https://github.com/SemperSupra/android-artifact-recovery/actions/runs/42315395444), source head `7bb1e838a9f408a748f9e60abc8b61b187d3b29a`, artifact 13550532717 | Publisher-signer-verified archive, ARM32 observed not requested ARM64, no Play-delivered/original ART runtime | `1c55a0110f66361d123c53f60047c22d749eca241ffc560c09377bbd88d8daea` |

Each ZIP was retrieved through the connected repository provider and verified for CRC and member inventory. A bounded normalized derived-only local report `cdr-chatgpt-real-derived-donor-differential/v2` has SHA256 `525bf4f729fcb05719dc1155e6b8172c24cb5006b06a9eaeb608c48e6e766abf` (15,355 bytes). This Git DLE records its acceptance findings independently of the local file.

## Corrective action 1: Linux ARM64 ASAR census parity

Previous R018 Linux ARM64 source branch extracted ASAR only for x64; the 3,643 ARM64 files vs 23,597 x64 files were **instrumentation bias**, not a product capability gap. Corrected in CDR Linux draft PR #15: all package architectures now extract/read the architecture-neutral ASAR and require a nonempty result; source-only native donor execution remains forbidden. All exact-head run steps completed success.

| Donor | Earlier files | R019 files | ASAR-extracted files (R019) |
|---|---:|---:|---:|
| Linux x64 DEB | 23,597 | 23,597 | 19,954 |
| Linux ARM64 DEB | 3,643 | 23,597 | 19,954 |
| Linux x64 RPM | 23,600 | 23,600 | 19,954 |
| Linux ARM64 RPM | 3,646 | 23,600 | 19,954 |

Re-qualified identical unique file-content SHA256 intersections: Linux DEB x64↔ARM64 **18,103 / 18,155 each (99.71% each)**. Linux ARM64 DEB↔macOS unified x64 **1,812**, but both denominator and package provenance differ. A hash establishes identical indexed bytes only, never runtime/feature/CRUD parity.

## Corrective action 2: actual native macOS Codex binary, not script wrapper

Earlier macOS scan selected the 328-byte POSIX shell script at `codex-cli/bin/codex` via `find -print -quit`, falsely treating launcher as candidate binary. CDR macOS draft PR #16 now uses fixed-size Mach-O magic/cputype classification, refuses ambiguous/invalid candidates, emits typed receipts, and includes seven source-owned negative tests.

Run #42317919989 passed native source tests, signature gating, donor static derivation, derived-only publication, and cleanup. Readback:

| Bundle | Selector result | Architecture | Native size | Native SHA256 |
|---|---|---|---:|---|
| Classic app | NO_NATIVE_MACHO_CODEX | N/A | N/A | N/A |
| Unified `ChatGPT-latest-x64.dmg` | NATIVE_MACHO_CODEX_SELECTED | x86_64 | 290,633,632 | `f08326a585b6b82a3d5951662bac6f78bf7b759639737d8464b3ac165195f846` |
| Unified `ChatGPT.dmg` | NATIVE_MACHO_CODEX_SELECTED | arm64 | 270,814,880 | `a636331ed87605efc4cf84028ac2884a75363f9d10ead63cffb57ea0016d486e` |

The bundled-vs-public standalone result is still NO_MATCHING_PUBLIC_RELEASE; the native executable was **never run**. Mac default-only computer-history, messages, record-and-replay plugin/MCP declarations remain static observations, not feature enablement.

## Corrective action 3: Android same-donor derivation drift

Two archived successful AAR public #37 jobs consumed the **same APKPure archive SHA256** `b05ceacd37481c95ef74a836394b1db9b69e19d360bbb119645ef949d44abb36`:
- Prior derived artifact 13541698546: 34,996 source files scanned, JADX 112 errors.
- Later artifact 13550532717: 34,741 source files scanned, JADX 106 errors.
- 30 feature marker categories and 5 protocol marker categories changed while nine library marker categories did not.

This is `SAME_DONOR_DERIVATION_DRIFT`, NOT evidence the original ChatGPT APK changed or a new app was recovered. AAR draft PR #37 now contains a single atomic commit `bf67249979dcd306ee787fd74c72b52905fbd71d` for a controlled single-thread JADX candidate plus explicit `derivation_config` receipt and configuration-aware repeatability guard. Its native job [#42318717821](https://github.com/SemperSupra/android-artifact-recovery/actions/runs/42318717821) was running at this R019 writing; **no terminal verdict presumed**. Preserve the old error counts and record old/new tool configurations before interpreting subsequent deltas.

## Remaining hard holds and next authority

- `ORIGINAL_RUNTIME_NOT_RUN`: no admitted signed original application pre-auth process/UI state/IPC or CRUD oracle, on any platform. Candidate sensors: process launch and pipe boundaries, permission prompts, local state before/after, MCP initialize/list-tools and cleanup; strict private session/cookie/credential exclusion.
- `LINUX_SIGNING_NOT_INDEPENDENTLY_ATTESTED`: official Linux install page documents signed repositories but no independently publisher-attested key fingerprint in the cited instructions; externally captured fingerprint is TOFU, not owner approval. Do not import/promote unreviewed GPG key.
- `ANDROID_PLAY_CURRENT_NOT_ACQUIRED / ARM64_NOT_VERIFIED`: APKPure historical archive has 12 ARM32 native ELF entries; neither Google Play provenance nor ART runtime validated.
- `CODEX_STANDALONE_MATCH_NOT_QUALIFIED`: compare pinned public release only when exact verifiable native artifact exists; not on matching launcher or same product version string.
- Keep existing PRs #11, #15, #16 (CDR) and #37 (AAR) draft. Obsolete duplicate CDR #10 closed unmerged after unique source retained. No new repo, paid/private CI, raw proprietary payload publication, unauthorized executor, forced merge or release.

DLE authority: `mark-e-deyoung/ghidra-tools#4`; CDR private `#59`; AAR private `#79`. Status `STATIC_DIFF_REQUALIFIED`; `ORIGINAL_APP_RUNTIME_UNQUALIFIED`; `NO_MERGE_OR_RELEASE_AUTHORIZED`.
