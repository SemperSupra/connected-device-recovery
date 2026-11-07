# R018 — ChatGPT four-platform original-package-derived differential (2026-11-07)

**Grade:** `OBSERVED_DERIVED_STATIC_METADATA_ONLY`. This is a read-only comparison of actual GitHub Actions *derived evidence ZIPs*, not a synthetic comparator fixture, original package execution, or ChatGPT service API/CRUD qualification. ZIP CRC readback passed for all five independently retained workflow artifacts.

## Pinned input receipts

| Donor | Source run | Artifact ID | Source head | Acquired ZIP SHA-256 |
|---|---:|---:|---|---|
| Windows x64 | [42315312266](https://github.com/SemperSupra/connected-device-recovery/actions/runs/42315312266) | 13550049417 | `98b7de5922ae442ea7152419e8dbe4b89877af95` | `2755d191e9e09868c15f47c37017963388001f9bfe2327fc660f6c42425466f5` |
| Windows ARM64 | same | 13549394358 | same | `30e02a9e5d200ed71e48df1b9d8685e3e8f99abb39cb0d93f707a939bdecfa3d` |
| Linux DEB/RPM, both architectures | [42305137506](https://github.com/SemperSupra/connected-device-recovery/actions/runs/42305137506) | 13545079581 | `f0181e10a6387cba61b34dc76a508db443826a46` | `7c2061dc87e4c03a76bf5a8f2561149e0bf569edf0abf9fcc739b8201f41c30e` |
| macOS Classic, unified x64, unified default | [42305182628](https://github.com/SemperSupra/connected-device-recovery/actions/runs/42305182628) | 13545109081 | `0a50825b1834fbfc939761fe81c8debbad9d1bbc` | `01badb1245b2f69c59cee981b9607606968adb916dda63154915b008f879d217` |
| Android APKPure archive | [42315395444](https://github.com/SemperSupra/android-artifact-recovery/actions/runs/42315395444) | 13550532717 | `7bb1e838a9f408a748f9e60abc8b61b187d3b29a` | `1c55a0110f66361d123c53f60047c22d749eca241ffc560c09377bbd88d8daea` |

Local normalized derived-only JSON verification receipt: SHA-256 `40bd968cd1ca063edb52201b7c83c19744fcf8e1d28fb3e04939c1569d4b7da2`; 13,675 bytes. Important measured conclusions are preserved below independently of that temporary local file.

## Measured differential

- Windows signed MSIX `OpenAI.Codex` **26.1103.3517.0** x64/ARM64: separate package SHA256; **identical ASAR structural counts**: 20,125 entries, 19,783 packed files, eight unpacked files and 334 directories. Both headers 5,336,128 bytes, but **header SHA256 DIFFERENT**; do not assert identical content or behavior.
- Linux four packages (DEB/RPM amd64/arm64) advertise `26.1103.32239` (RPM release suffix `-1`). Both RPMs `RPM_SIGNATURE_KEY_UNAVAILABLE`; DEBs `DEB_PACKAGE_AUTHENTICITY_NOT_VERIFIED`. No RPM/DEB author trust promotion.
- macOS unified x64 `ChatGPT-latest-x64.dmg` and default `ChatGPT.dmg` advertise `26.1103.32239`, matching Linux version string but NOT necessarily deployment/version identity beyond that. Separate historical Classic `com.openai.chat` is `1.2026.184`.
- Android `com.openai.chatgpt` source `apkpure` (not Google Play delivery), signer reported verified, **12 ELF objects with observed `armeabi-v7a` vs requested `arm64-v8a` => NATIVE_ABI_MISMATCH**; JADX `JADX_RETURNED_ERRORS_PARTIAL_EVIDENCE` (106 reported errors). No ART/GUI/IPC/CRUD protocol promotion.
- Same-content SHA256 intersections of sanitized **file inventories** (unique file-hash values; not counts of matched paths or executable functions):

| Left donor | Right donor | Identical unique file hashes | Coverage in left | Coverage in right |
|---|---|---:|---:|---:|
| Linux x64 DEB | Linux x64 RPM | 18,154 | 99.99% | 99.98% |
| Linux ARM64 DEB | Linux ARM64 RPM | 1,981 | 99.90% | 99.85% |
| Linux ARM64 DEB | macOS unified x64 | 1,811 | 91.33% | 79.36% |
| macOS unified x64 | macOS unified default DMG | 2,150 | 94.22% | 93.48% |

## R019 caveats discovered by auditing the source scanners

**Linux x64/ARM64 inventory extraction was not equivalent in R018.** The Linux workflow had an x64-only ASAR extraction condition. Of 23,597 Linux amd64-DEB file records, the x64 census had 19,975 paths absent from ARM64 and ARM64 had 21 paths absent from x64 (net 19,954 more x64 records), dominated by 19,000+ `__app_asar_extracted` files; the ARM64-DEB inventory had only 3,643 file records because ASAR wasn't expanded. This is **sensor coverage bias**, not an app capability difference. Unique SHA intersections reported above remain valid as **lower-bound observed-content matches**, but cross-architecture coverage and absence in ARM64 MUST NOT be inferred from this R018 inventory. Linux owner PR #15 commit `c6ae89cdc50ac4449a25d9edb4ed0bf76dd8d91d` removes the architecture gate and requires non-empty ASAR output; run qualification and re-derive symmetric coverage before promotion.

**macOS bundled Codex comparison had selected a wrapper, not the native binary.** Existing `codex-comparison.json` selected `codex-cli/bin/codex`, a **328-byte POSIX shell script** present in both unified DMGs. Full static file census separately observed actual `codex-cli/CodexCLI.app/Contents/MacOS/codex` executable candidates of **290,633,632 bytes** (x64 DMG) and **270,814,880 bytes** (default DMG). The old binary comparison is therefore unqualified, despite the workflow's overall success. macOS owner PR #16 commit `d5f1085e02dddc2a90b401c93cabab288e598c33` introduces a bounded non-executing Mach-O selector with source-known negative controls. Await exact-head native validation and inspect new selection receipts before claiming bundled Codex identity.

These are corrected source/evidence design defects; previous exact-head CI successes for old source remain historical, not evidence that their scanner conclusions were complete. No original app runtime or source code was executed/published.

## Differential plugin descriptor discovery (static-only)

Parsing sanitized `plugins.json` preserves duplicate names as a **multiset of SHA256 descriptor hashes**. The `unified-computer-use` name legitimately appears twice with different descriptor hashes; a plain dictionary keyed by plugin name would overwrite evidence.

- Linux x64 versus Linux ARM64: **seven distinct shared named plugin sets**, all seven byte-identical as descriptor multisets.
- Linux versus macOS unified x64: **seven shared names, all seven identical descriptor multisets**; macOS x64 additionally declares `computer-use`.
- macOS unified x64 versus macOS default DMG: **eight shared names, all eight identical descriptor multisets**. Default DMG additionally declares **`computer-history`, `messages`, and `record-and-replay`**, with corresponding additional MCP manifest entries; two corresponding extra skill files (`computer-history`, `record-and-replay`) are observed.
- Linux versus macOS default DMG: shared seven named plugin descriptor sets are byte-identical; default macOS additionally declares `computer-use`, `computer-history`, `messages`, `record-and-replay`.

These names identify bundled descriptor presence only. **Do not infer install-time activation, service backend access, capabilities granted, functional parity, runtime IPC, or end-user availability.** Architecture of the default macOS DMG must not be guessed from its URL.

## Additional MCP process-launch clues (static config only)

The default macOS DMG's three additional `.mcp.json` manifests describe server IDs `computer-history`, `messages`, and `event-stream`. Each uses command basename `computer-use-client-launcher` with a **two-argument** launch shape; the normalized descriptors show **no explicit URL host** or environment-key entries. This is a plausible local process/pipe sensor candidate, **not evidence that any process was launched, server advertised tools, or data/state was accessed**.

In the shared baseline, `codex_app` declares `launch_codex_app_tools_mcp` (one argument) and `cua_repl` declares `node` (zero arguments). Their matching presence in both macOS DMGs helps isolate the three additional launcher-surface declarations in the default DMG.

Next runtime test, when authorized/admitted: capture redacted OS-level process/argv identity, inherited file descriptors and IPC transport, MCP initialize/list-tools exchanges, denied-permission cases, and state/CRUD effects with independent ground truth and cleanup. Treat all free-form arguments and payloads as potentially sensitive; never upload credentials, actual user conversations or content.

## Live test/code and next handoff

- Public CDR #11 source-only four-platform receipt comparator `tools/compare_chatgpt_platform_receipts.py` previously passed source-negative controls at exact head `c608cd526a5edf937301903baf75f1c645c95897`, [run 42315746474](https://github.com/SemperSupra/connected-device-recovery/actions/runs/42315746474). It captures package/signer/ABI/version but not file hash/component equality.
- A reusable static plugin-manifest multiset comparator and negative tests have now been added to #11 as `tools/compare_desktop_plugin_manifests.py` and its test, with dedicated source-only CI; qualify exact head after all writes.
- Next qualify **the observed macOS default-only plugin/MCP descriptors at original runtime**, with independent process/IPC/local state/CRUD sensors and permissions envelope, only on admitted authenticated-free workloads. Compare shared components by content hash and frozen feature hypotheses; retain any missing/unknown as `NOT_OBSERVED`, not absence.
- Keep Linux signing holds, Android arm32/current Play/ART holds and Windows/Mac actual GUI/session execution holds. Repository issue authority: `mark-e-deyoung/ghidra-tools#4`; source owner: `SemperSupra/connected-device-recovery-private#59`; Android owner: `SemperSupra/android-artifact-recovery-private#79`. Do not publish raw binaries, secrets, ASAR contents, credentials or session data.

**Verdict:** `STATIC_DIFFERENTIAL_REP_PASS`; `ORIGINAL_RUNTIME_NOT_RUN`; `PROTOCOL_STATE_CRUD_NOT_VERIFIED`; `NO_MERGE_OR_RELEASE_AUTHORIZED`.
