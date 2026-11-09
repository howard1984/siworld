# Windows native miner

Status: implementation for engineering-network qualification. Local build artifacts are test packages, not public releases. A build is not evidence of Windows 10/11 hardware acceptance or successful mining. The first package is unsigned and installs no service or GUI.

## Requirements

Windows 10/11 x86_64, a CPU and operating system supporting x86-64-v3 (including AVX2), at least four logical processors, and at least 30 GiB of OS-visible physical memory are required. Install 32 GB or more; reserved hardware memory can reduce the visible total. A generic x86-64 launcher checks admission before it starts the optimized proving executable. There is no scalar fallback. Both binaries use the static MSVC runtime.

Keep the computer powered and awake during mining. Initial chain replay verifies native proofs and can take substantially longer than downloading blocks. Proof generation also uses considerable memory. No Windows performance qualification is claimed yet.

## Package verification and startup

1. Download the ZIP, `provenance.json` and `SHA256SUMS` from the same reviewed local build. In PowerShell, run `Get-FileHash .\siworld-miner-windows-x86_64.zip -Algorithm SHA256` and compare all 64 digits with the published checksum and provenance archive digest. Verify the provenance commit and local build method against the trusted build record. Obtain the expected checksum through a trusted distribution channel. Extract the entire package, retaining `libexec`.
2. Run `.\siworld-miner.exe --check-hardware` from PowerShell or `siworld-miner.exe --check-hardware` from CMD. Run `--help` for requirements without starting proof code. Administrator privileges are not needed.
3. Obtain the reviewed engineering-network bundle through the operator's private distribution channel. Run `.\siworld-miner.exe --network-bundle .\engineering-network.json`. Do not use a bundle supplied by an untrusted peer. The immutable rules, genesis identifier, signed descriptors and pins are checked before initialization. The package does not include live node addresses.
4. Select `1` for Holder or `2` for Voyager. There is no default. Holder rewards have additional long locks under the existing protocol; selection changes local template preferences only.
5. Choose `1` to create or unlock an encrypted local wallet, or `2` to paste an existing complete `sivf1` receiving address. For a new wallet, record the recovery words offline, complete the randomized word challenge, then choose `1` to confirm the offline backup. Passwords, recovery words and recipient addresses are not written to terminal logs. The program cannot prevent operating-system recording, screen capture or compromised terminal software. If a saved local wallet exists, choice `1` unlocks and reuses it without overwriting it.
6. Give only `%LOCALAPPDATA%\SIWORLD\pairing-public.json` to the bootstrap operator through the agreed channel. It contains a public node identity, not wallet custody. The operator must independently approve its pin in the existing peer configuration, with dialing disabled for this outbound-only peer. Until that pairing is complete the miner waits for authenticated peers. No programmatic request changes the remote node.
7. Choose `1` to start. Leave the terminal open. The miner authenticates an outbound connection, synchronizes and independently verifies the chain, prepares a template and searches PoW. No inbound socket, port mapping or firewall rule is created.

These seven operator steps are the documented route; actual download-to-PoW duration remains unmeasured. Pairing and synchronization are dependencies, so the start confirmation does not imply immediate hashing.

## Local data and stopping

State is stored in `%LOCALAPPDATA%\SIWORLD`. New directories and files are created with a protected current-user-only DACL. Opens reject unsafe ownership, broadened ACLs, reparse points, alternate streams and multiply linked files. This does not defend against administrator access, malicious software running as the same user, paging or disk theft. Keep normal host protection enabled.

The foreground lease prevents a second setup session from changing a live miner's destination. Ctrl+C or Ctrl+Break requests a run-bound clean stop. The foreground waits for the owned proof operation, networking cleanup and independent final replay. Closing the terminal or shutting down Windows can interrupt that process; use Ctrl+C and wait for the explicit clean-stop result. A missing foreground process also causes the worker to request a clean stop. Existing evidence is preserved after errors. Never delete the data directory to clear an error without retaining an offline copy and recovery material.

The saved wallet can be reused after restart. An existing receiving address can also be pasted without giving its spending keys to the miner. Preserve network and account recovery context along with the offline words; a password encrypts the vault and does not define its address. No automatic key rotation, repair or network migration occurs.

## Display semantics

The program uses English numbered menus. Enter 1 or 2 and press Enter to choose a reward mode and address source; no default is selected. Backup and start confirmations each require an explicit choice of 1. Existing text choices remain accepted. Passwords, receiving addresses and recovery words remain hidden inputs.

The live display samples every five seconds and prints a new snapshot only when its visible content changes. An ASCII activity indicator updates between snapshots in an interactive console at least 50 columns wide. Narrow consoles and redirected output retain plain text. The animation identifies peer waiting, synchronization, template preparation and proof search separately; it does not imply measured progress. Stale observations stop showing an active phase. A missing authenticated connection identifies the public pairing file and states that mining has not started. It reports the verified local height, current peer batch goal (unverified until applied), authenticated peers, effective PoW attempts per second, main-chain local-produced block count and detached block count. Effective hashrate includes template waits and is not the number of internal proof/hash rounds. Startup, counter discontinuities, clock anomalies and observations older than fifteen seconds show unavailable rather than a fabricated zero.

Rewards are authenticated from durable local production receipts and current canonical membership. A candidate receives no credit. Detached blocks are removed from accepted totals. Amounts use integer atoms, displayed with eight decimals in SIP. The categories are cumulative mature earned, pending maturity and long-term locked; they are **not an unspent wallet balance** and do not subtract later wallet spending. The next unlock uses verified block height, not wall-clock time. A stale display cannot establish current mining or reward status.

Example conditions:

- Insufficient memory: startup stops before proof work and prints the measured MiB and the 30 GiB requirement in English.
- Waiting for authenticated peers: verify connectivity and complete public identity pairing; do not disable authentication or open inbound ports.
- Synchronizing: the displayed batch goal is only a peer hint. The miner waits for authenticated synchronization before preparing PoW.
- Worker checksum mismatch: stop using the package and verify/download it from the trusted release channel.
- Vault authentication or storage ownership error: preserve data, verify the password and local permissions, and request diagnosis. No replacement wallet is silently created.
- Clean stop pending: the current proof cannot be safely preempted. Keep the terminal open until the final verified result.

## Building and automated checks

Miner packaging and execution are excluded from GitHub Actions. Development packages use an owner-controlled Mac with `cargo-xwin` or a native Windows MSVC host, the pinned Rust toolchain, locked cached dependencies and the `x86_64-pc-windows-msvc` target. Both binaries use `-C target-feature=+crt-static`. The PE audit rejects dynamic VC/UCRT and unreviewed non-system DLL imports.

Run `python3 scripts/build-windows-miner.py --expected-commit <full-commit> --output <new-directory>` from a clean checkout. On Mac, install the cross-toolchain and cache dependencies before the offline build. The script records the source commit, tracked-source hashes, compiler, build method, worker hash and flags. The inner checksums cover package contents; the outer checksums bind the ZIP and provenance record. The script rejects CI and runner environments and never claims a hosted build. Cross-compilation does not run Windows executables or establish Windows compatibility.

Windows 10/11 testing must measure startup through valid proof-of-work, actual protection prompts, sustained mining, an accepted block, and reward/lock display separately. Build metadata and synthetic unit tests are insufficient.

## Native dependency inventory

The locked default-feature Windows worker graph contains the following native-code components. Source inspection establishes an MSVC build path; a complete default-feature Windows build and final import audit remain the executable compatibility gate.

| Component | Native inputs and use | MSVC and static CRT path |
| --- | --- | --- |
| `aws-lc-sys 0.47.0`, through `aws-lc-rs 1.19.0` | AWS-LC cryptographic C code and x86-64 assembly for authenticated networking and native cryptography; the vendored tree also contains C++ support and test sources, not all of which enter this build | Explicit `x86_64_pc_windows_msvc` bindings and `builder/cc_builder/win_x86_64.rs`; C compilation uses MSVC through `cc`, or CMake's MSVC path with `CMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded`. Native Windows builds require NASM and disables prebuilt NASM fallback so assembly is built on the build host. |
| `blake3 1.8.7` | Native SIMD hash implementations, including Windows assembly and C fallback sources | `build.rs` selects `*_windows_msvc.asm` through MSVC `ml64.exe` and `cc`; CRT-bearing C objects inherit `crt-static`. A pure Rust feature exists for diagnostic builds. |
| `cc 1.10.0`, with `cmake 0.1.58` and `find-msvc-tools` | Build tools, not linked mining runtime libraries; `cc` contains small C/C++ compiler detection probes | The `cc` build helper maps `CARGO_CFG_TARGET_FEATURE=crt-static` to `/MT`; CMake propagates the compiler configuration. These tools belong on the build host, not the end user's machine. |

`ring 0.17.14` appears in the lock resolution but is not active in the default-feature Windows worker dependency tree. It must not be reported as a currently compiled component. Its optional path has MSVC support, but enabling it requires a new dependency and import audit. `libcrux-ml-kem`, `libcrux-ml-dsa`, `libcrux-sha3` and `libcrux-intrinsics` use Rust implementations/intrinsics in this graph, not a C/C++ library. Windows binding crates link Windows system import libraries. No incompatible active native component has been identified by source inspection; this is not a claim that the full MSVC build has passed.

Required build-host tools are MSVC x64 C/link tools and `ml64`, the Windows SDK, NASM, CMake, Python and the pinned Rust toolchain. CI installs checksum-pinned NASM 2.16.03 in its temporary tools directory; CMake and MSVC come from the hosted image. These tools are not included in the package and are not required on miners' computers. Missing Windows headers or `ml64` on a Mac is a missing cross-toolchain component, not evidence of source incompatibility. If MSVC fails, retain the compiler error and identify the dependency before proposing a replacement. BLAKE3's pure Rust implementation is a possible fallback for its native build failure; changing the cryptographic transport/provider requires separate compatibility review rather than silently replacing AWS-LC.

A `--no-default-features --features portable-hash` diagnostic build can type-check the Windows terminal and storage code without the C transport dependency. It rejects mining and is never packaged. This diagnostic does not replace a complete Windows MSVC build, the default authenticated transport tests or executable acceptance.

## Physical-machine acceptance

Qualify the same official ZIP separately on one clean Windows 10 x86_64 machine and one clean Windows 11 x86_64 machine. Neither machine may have an additionally installed VC++ Redistributable, Rust, Python, Visual Studio, WSL or Docker used to satisfy package dependencies. Inbox Windows components are expected. Extract and run `--help`, `--check-hardware`, the onboarding flow and the default authenticated worker without installing additional software. A missing-DLL dialog, runtime-install request, or failed worker launch fails this gate. Do not remediate a failed gate by installing a runtime and then label the machine clean. Hardware admission alone does not exercise the worker.

| Required clean-system evidence | Windows 10 | Windows 11 |
| --- | --- | --- |
| OS edition/build and clean image origin; no added runtime/tooling | Pending | Pending |
| Official ZIP SHA-256, commit and Actions run/attempt | Pending | Pending |
| Extracted launcher and worker run with no added component | Pending | Pending |
| Defender/SmartScreen outcome, firewall prompt and exact elapsed onboarding time | Pending | Pending |

Run sustained mining on a real Windows machine for at least 24 continuous hours, with at least one canonical accepted block and authenticated correct reward and lock display. Record which OS performed this sustained run separately from the two clean-start checks. Retain private run evidence without uploading keys, raw recipient addresses, peer endpoints or linkable network/transaction records. No physical-machine result has been recorded yet.

Record Windows edition/build, CPU, physical and visible RAM, logical processors, package checksum, each onboarding step and elapsed download-to-effective-PoW time. Record cold-sync height/time separately from template preparation and PoW. Check Ctrl+C and restart, duplicate launch, network loss, stale status, rejected wrong-password resume, and preservation of the same backed-up address.

Defender and SmartScreen outcomes are pending actual observation. Verify the package source and checksum first. If an unsigned-package SmartScreen reputation warning offers **More info → Run anyway**, proceed only for that verified package. If Explorer shows **Properties → Unblock**, it can remove the download mark for that verified file; it does not override an antivirus verdict. A Defender detection is a failed acceptance item pending investigation: do not disable protection or add a global exclusion. Record the exact warning and detection name without secrets. Report actual results rather than assuming warnings will or will not occur.
