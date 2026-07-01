# pyrxd Security Documentation

**Consolidated from:** `SECURITY.md` (policy), `docs/threat-model.md`, `docs/security-audit-scope.md`, `docs/security-review-playbook.md`, `docs/red-team-checklist.md`.

---

# Part I — Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in pyrxd, please report it
**privately** rather than filing a public GitHub issue.

Send disclosure to: **security@mudwoodlabs.com**

Include:

- A description of the issue and its impact
- Reproduction steps or a proof-of-concept
- Affected versions of pyrxd (and Python, if relevant)
- Your name / handle for credit (optional — anonymous reports accepted)

We aim to:

- Acknowledge receipt within **2 business days**
- Provide an initial assessment within **7 business days**
- Coordinate a fix and disclosure timeline based on severity, typically
  within **90 days** following Google Project Zero norms

We will publicly credit reporters in the changelog and security
advisories unless you request otherwise.

Our internal handling steps — triage, private fix, coordinated disclosure,
and release — are documented in
[`docs/runbooks/incident-response.md`](docs/runbooks/incident-response.md).

## Scope

Security reports are welcome on:

- Cryptographic primitives in `pyrxd.curve`, `pyrxd.security`,
  `pyrxd.aes_cbc`, `pyrxd.crypto`
- Key derivation in `pyrxd.hd` (BIP32/39/44)
- Transaction construction and signing in `pyrxd.transaction`,
  `pyrxd.script`
- Glyph token protocol handling in `pyrxd.glyph`
- Gravity Protocol covenant code in `pyrxd.gravity`
- Network code in `pyrxd.network` (ElectrumX client)

Out of scope:

- Vulnerabilities in dependencies (please report to the upstream project)
- Social-engineering attacks against pyrxd users or maintainers
- Issues requiring physical access to a victim's device
- Issues already documented in the public CHANGELOG or issue tracker

## Status

pyrxd is **pre-1.0 software**. The cryptographic primitives have not
been independently audited. Use at your own risk for production
deployments. The library is in active development; APIs may change
between minor versions before 1.0.

If you are deploying pyrxd in a production system handling real funds:

- Pin to a specific commit SHA in your `pyproject.toml` / requirements
- Run integration tests against a regtest or testnet network before
  any mainnet broadcast
- Hold private keys outside the web tier — see the architectural
  pattern in our README under "Production Architecture"
- Subscribe to GitHub Security Advisories for this repository

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.2.x   | ✅ Yes (current) |
| < 0.2   | ❌ No (pre-public release; do not use) |

Once we reach 1.0, the policy will move to a published support window
covering at least the current major and the most recent minor of the
prior major.

---

# Part II — Threat Model

**Version:** 1.0 (draft)
**Last updated:** 2026-05-01
**Applies to:** pyrxd v0.3+ (library + CLI)

This document is the working threat model for pyrxd. It exists to:

1. Make explicit what pyrxd protects, and from whom.
2. Map every claimed protection to a concrete control in the codebase.
3. Surface gaps honestly so users, contributors, and (eventually) auditors can see what is and isn't covered.
4. Provide a starting point that an external security review can build on rather than recreate.

This is the threat model for experimental open-source software, provided as-is under the [LICENSE](LICENSE), that people can choose to use. It is not a substitute for an independent third-party audit. The README states cryptographic primitives have not been independently audited; that remains true.

## Purpose & non-goals

### What pyrxd is

A Python SDK + CLI for the Radiant blockchain. It performs:

- Key generation, derivation, and signing (secp256k1, BIP32/39/44)
- Transaction construction, serialization, and signing
- Glyph token protocol operations (NFT mint, FT deploy, transfers)
- Gravity cross-chain BTC↔RXD atomic swaps
- SPV verification of Bitcoin transactions
- ElectrumX networking and Bitcoin data-source queries

### What pyrxd is NOT

- Not a hardware wallet integration
- Not a multi-signature coordination tool (single-sig only in v0.3)
- Not a node implementation (does not validate the chain itself; relies on ElectrumX)
- Not a custodial service or a smart-contract platform beyond what Radiant's consensus rules support

### Non-goals (explicit)

These are not protected by pyrxd controls:

- **Coercion attacks** (rubber-hose, $5 wrench attacks)
- **Physical attackers** with hands on the user's machine
- **Side-channel attacks at the silicon level** (Spectre/Meltdown class)
- **Compromise of the user's terminal emulator, OS, or hardware**
- **Compromise of the BIP39 wordlist file or scrypt KDF** (we trust upstream implementations)
- **Long-term post-quantum security** (secp256k1 itself is not post-quantum safe)

## Assets

Ranked roughly by value to an attacker:

| # | Asset | Form | Where it lives |
|---|-------|------|----------------|
| A1 | BIP39 mnemonic | 12 or 24 words | User's memory, paper, optionally encrypted in `wallet.dat` |
| A2 | BIP39 seed (PBKDF2 of A1) | 64 bytes | In-memory `SecretBytes` only; never persisted directly |
| A3 | Account-level xprv | base58check string | Derived in-memory from A2; never persisted |
| A4 | Per-address private keys | 32-byte scalar | Derived in-memory from A3; never persisted |
| A5 | Encrypted wallet file (`wallet.dat`) | AES-GCM-encrypted JSON | Disk at `~/.pyrxd/wallet.dat`, mode 0600 |
| A6 | Account-level xpub | base58check string | Watch-only-safe; can be exported via `wallet export-xpub` |
| A7 | An unsigned transaction | bytes | Transient; held in-memory during tx building |
| A8 | A signed transaction in flight | bytes | Transient; sent over wss to ElectrumX |
| A9 | UTXO ownership info | tuples (txid, vout, value, owner) | In-memory after `collect_spendable()`; on disk in `addresses` dict of wallet.dat |
| A10 | Network metadata (which addresses, balances, history) | observable on-chain | Public, but linkability matters for privacy |
| A11 | Unlocked wallet held by the signing agent | in-memory `HdWallet` (seed in `SecretBytes`) | The `pyrxd agent` daemon process, for the unlock window only; reachable via a `0600` Unix socket |

Control surfaces target the upper rows; A6 is intentionally exportable; A10 is unavoidable on a public chain.

## Threat actors

### TA1: Local post-compromise malware

**Capabilities:** read process memory, read files in `$HOME` with user permissions, tamper with stdin/stdout, modify dependencies on next install, exfiltrate over network.

**Goals:** A1, A2, A4, A5.

**Reach:** Once present, can do almost anything. pyrxd's controls provide **defense in depth at best**, not prevention. Encrypted wallet file slows exfiltration; `SecretBytes.zeroize()` slightly reduces window; nothing makes a compromised host safe.

### TA2: Local non-malicious user (footgun)

**Capabilities:** the user themselves making mistakes — pasting mnemonics into chat, running `wallet new` while screen-sharing, copying to clipboard, leaving terminal scrollback.

**Goals:** Not adversarial; a victim of accident.

**Reach:** Heavy. Most reported real-world key losses come from this category. pyrxd's job is to make accidents harder.

### TA3: Network passive observer

**Capabilities:** sniff packets between user and ElectrumX/BTC data sources.

**Goals:** A10 (link addresses to user's IP), inputs/outputs for chain analytics.

**Reach:** Limited if `wss://` is enforced (TLS). pyrxd defaults to `wss` and rejects `ws://` without `allow_insecure=True`.

### TA4: Network active MITM

**Capabilities:** intercept and modify traffic. Possible against `ws://` (rejected by default) or against TLS with a CA compromise.

**Goals:** Substitute attacker addresses into broadcast txs, suppress balance/history results to confuse the wallet, force fee bumps.

**Reach:** Mostly mitigated by TLS but degrades to TA5 if the user is using a hostile ElectrumX.

### TA5: Hostile ElectrumX operator

**Capabilities:** The remote endpoint pyrxd connects to. Can lie about anything it returns: balances, UTXO sets, transaction confirmations, headers. Cannot forge signatures or steal private keys.

**Goals:** Selective service denial (refuse to broadcast a tx, drop history queries), inducing wallet to derive new addresses (privacy attack), trickery to lure UTXOs into a malformed tx (limited by client-side validation).

**Reach:** Significant for privacy, limited for theft. The default config uses one public ElectrumX server (`electrumx.radiant4people.com`) which is a single point of trust.

### TA6: Hostile Bitcoin data source

**Capabilities:** A `BtcDataSource` (mempool.space, blockstream.info, Bitcoin Core RPC) used by Gravity for SPV proofs. Can lie about BTC-side data.

**Goals:** Forge a "BTC was sent" proof that fools the RXD-side covenant into releasing funds.

**Reach:** A self-consistent forged chain is byte-identical from every source, so `MultiSourceBtcDataSource` quorum — which only detects *disagreement* between sources — does **not** catch it. The actual forgery defense is the on-chain covenant's `expectedNbits` pin, now mirrored in the Python verifier (`verify_chain` enforces the nBits pin *before* PoW, audit F-01/F-03), with the Merkle-proof↔header binding (`build(tx_block_height=…)`, F-18) and an offer-time difficulty floor (`reject_low_difficulty`/`min_difficulty_nbits`, F-02). For confirmation depth, a single source under-reporting `block_height` inflates burial; the `[1,tip]` floor on `get_raw_tx` plus the above-dust `MultiSourceBtcFundingReader` quorum (F-17) mitigate it. The primitive must **not** be the sole release authority on a value-bearing chain without a covenant pinning nBits — enforced by `require_spv_sole_authority_cleared`. Full pitfall catalogue: [`docs/how-to/spv-verification-pitfalls.md`](docs/how-to/spv-verification-pitfalls.md).

### TA7: Hostile metadata file author

**Capabilities:** Crafts a `metadata.json` and convinces the user to mint/deploy from it.

**Goals:** Make the user broadcast a transaction that locks funds or tokens to an attacker key without the user noticing. Crash the CLI with malformed CBOR. Embed a malicious URL or script reference.

**Reach:** Real and underappreciated. The user types `pyrxd glyph mint-nft alice-token.json` and trusts that the resulting token belongs to *them*. If the file's `owner_pkh` is the attacker's, the NFT is the attacker's.

### TA8: Hostile counterparty (Gravity)

**Capabilities:** The other party in an atomic swap. Wants to take both legs of the trade.

**Goals:** Exploit covenant bugs, race conditions, or incorrect SPV verification to claim BTC and RXD without delivering their side.

**Reach:** Direct financial impact if a bug exists. This is the single most adversarial setting in pyrxd. Mitigated by the covenant tests in `tests/test_gravity_red_team.py` (1500+ lines), but the README flags Gravity as "still being hardened" and "covenant variants" as work in progress.

### TA9: Supply-chain attacker

**Capabilities:** Compromise a release of `coincurve`, `Cryptodome`, `click`, `cbor2`, `aiohttp`, `websockets`; typosquat `pyrxd` on PyPI; or compromise pyrxd's own release pipeline.

**Goals:** Inject signing-time backdoor, exfiltrate seeds via network, replace key derivation with attacker-controlled values.

**Reach:** Catastrophic if successful. pyrxd's defenses are limited to: small dep tree, `pip-audit` for known CVEs, signed PyPI uploads, and trust in upstream maintainers. We do not pin transitive deps.

## Trust boundaries

Listed roughly inside-out; each is a place where data changes from "untrusted" to "validated and used":

1. **CLI argv** → parsed by click, validated by command handlers. Click handles type coercion for `int`, `float`, `Path`, `Choice`. Custom validation (address shape, ref shape) is in command bodies.
2. **Stdin** → mnemonic and passphrase input via `click.prompt(hide_input=True)`. Normalized via `_normalize_mnemonic` (whitespace collapse). Validated by `bip39.validate_mnemonic`. Never logged.
3. **Configuration files** → `~/.pyrxd/config.toml` parsed by stdlib `tomllib`. Schema-checked by `Config` dataclass. Mode permissions on parent dir checked.
4. **Wallet file (`wallet.dat`)** → AES-GCM authenticated decryption; tag mismatch raises before any post-decrypt code runs. File mode checked (0o600 required) before read.
5. **Metadata files (`metadata.json`)** → JSON parsed with stdlib. Protocol names mapped to `GlyphProtocol` ints. Validated by `GlyphMetadata.__post_init__`. Cap on payload size enforced by `decode_payload`.
6. **Network: WebSocket frames from ElectrumX** → JSON-RPC framed, size-capped at 10 MB. Response correlation is per-id (concurrent calls don't swap responses). Hex/bytes results validated as typed values (`Txid`, `RawTx`, `Hex32`).
7. **Network: HTTP responses from Bitcoin data sources** → Content-type checked, size-capped, hex-decoded with explicit length. URL construction uses `urllib.parse.quote`.
8. **Library API surface (caller → pyrxd)** → typed validation at constructors: `Hex32`, `Hex20`, `Txid`, `Satoshis`, `Photons`, `BlockHeight`, `Nbits`, `SighashFlag` all reject malformed inputs at construction. `PrivateKey`, `PublicKey` validate input bytes/strings.
9. **Internal: pyrxd → coincurve / Cryptodome** → these libraries are the trust root for crypto primitives. We do not re-implement.

## Threat scenarios

Each scenario lists actor → action → asset → control(s) → residual risk.

### S1: Mnemonic exfiltration via JSON-mode redirect (TA2)

- **Action:** User runs `pyrxd wallet new --json --yes | tee mnemonic.txt` to "save" the output, mnemonic ends up unencrypted on disk.
- **Asset:** A1.
- **Control:** README documents the pitfall explicitly. The default (interactive) flow shows the mnemonic with an Enter gate — no shell-redirect exposure.
- **Residual risk:** User error remains possible. Mitigation is documentation, not enforcement. Documented at `README.md#security-scripting-wallet-new-with---json---yes`.

### S2: Mnemonic exposure via terminal scrollback (TA2)

- **Action:** User runs interactive `pyrxd wallet new` in tmux/screen with scrollback enabled.
- **Asset:** A1.
- **Control:** README documents that interactive display still has terminal-history risks. Enter gate slows down accidental copy.
- **Residual risk:** High. We cannot clear scrollback portably.

### S3: Mnemonic exposure via clipboard manager (TA2)

- **Action:** User copy-pastes the mnemonic from terminal display; clipboard manager retains history.
- **Asset:** A1.
- **Control:** None in v0.3.
- **Residual risk:** Real. Tracked as [issue #11](https://github.com/Radiant-Core/pyrxd/issues/11) — add a clipboard-hygiene warning after the Enter gate.

### S4: Wallet decryption attempt with wrong mnemonic (TA1)

- **Action:** Attacker has wallet.dat (e.g., from backup leak). Tries to decrypt with random mnemonics.
- **Asset:** A5 → A1.
- **Controls:** scrypt KDF (n=2^14) imposes per-attempt CPU+memory cost; per-file salt prevents precomputed table reuse; AES-GCM tag detects all wrong guesses. Decrypt failure surfaces a single static message — never echoes attacker input.
- **Residual risk:** scrypt parameters are tuned for "BIP39 seed has 128+ bits of entropy" — they slow brute force but do not save a mnemonic that's been leaked elsewhere.

### S5: World-readable wallet file post-restore (TA1)

- **Action:** User restores wallet.dat via `cp` or `rsync`; file ends up at mode 0o644.
- **Asset:** A5.
- **Control:** Load-time mode check refuses to read a wallet file with group/other read bits and prints the chmod fix. Test: `tests/test_hd_wallet.py::test_load_rejects_world_readable_wallet_file`.
- **Residual risk:** macOS/Windows behavior may differ; check is gated to `os.name == "posix"`.

### S6: Stale signature attack via fee-pass interleave (architectural)

- **Action:** A bug in tx builder that signs trial outputs but builds final outputs differently. Attacker pays fee on user's trial-tx not their actual one.
- **Asset:** A4 + A8.
- **Control:** Two-pass fee algorithm explicitly resets `unlocking_script` between trial and final, then re-signs. Documented in `tests/test_preimage.py`. Tested in `RxdWallet` and `HdWallet` send/send_max paths.
- **Residual risk:** Any new tx-builder code path must follow the same pattern. Code review item.

### S7: Hostile metadata.json owner_pkh substitution (TA7)

- **Action:** User downloads `nft-metadata.json` from chat. The file contains the attacker's `owner_pkh` (or the metadata triggers a tx whose change goes to the attacker). User runs `pyrxd glyph mint-nft nft-metadata.json` and broadcasts.
- **Asset:** A8, indirectly the minted NFT.
- **Controls:**
  - Confirmation prompt before broadcast shows "funding utxo, funding value, commit value, network." This summary does NOT currently surface the embedded `owner_pkh` from the metadata.
  - `init-metadata` scaffolds a clean template that the user fills in themselves.
  - Out-of-band trust (user shouldn't run hostile files).
- **Residual risk:** Real. **Open finding:** the broadcast summary should display the resolved `owner_pkh` (and ASCII-render the address) before the user confirms. Tracked as a follow-up; will become an issue.

### S8: Hostile ElectrumX returns malformed UTXO record (TA5)

- **Action:** ElectrumX returns a UTXO with a value that doesn't match the on-chain truth. User signs a tx using that fake value.
- **Asset:** A4 (signs a misweighted tx).
- **Control:** None at the wallet layer; pyrxd does not independently re-fetch source-tx outputs to verify UTXO values for plain RXD sends. Gravity does this for BTC inputs via `MultiSourceBtcDataSource` quorum.
- **Residual risk:** Real but bounded. A lying ElectrumX can cause the user to overpay fees or build invalid txs (which the network rejects on broadcast — funds aren't lost, just confused). Cannot induce theft directly because the locking script is what controls the funds, and pyrxd builds locking scripts itself.

### S9: Hostile ElectrumX claims address is unused (TA5)

- **Action:** During gap-limit scan, ElectrumX returns empty `get_history` for an address that is actually funded. Wallet thinks address is unused; recommends it for next receive (or for change).
- **Asset:** A10 (privacy: linking sender to receiver).
- **Control:** Library N5 fix: `_scan_chain` re-raises `NetworkError` on lookup failure rather than silently treating as "unused." Re-using a known-funded address is impossible because the gap-limit logic stops at consecutive empty results, and each empty result is verified.
- **Residual risk:** A *consistently* lying ElectrumX could still hide history. Mitigation is network-layer source diversity (use multiple servers); not implemented for ElectrumX queries (only for BTC data sources). Tracked as a future enhancement — multi-source ElectrumX.

### S10: Hostile counterparty exploits a Gravity covenant bug (TA8)

- **Action:** Counterparty crafts a swap proposal that, if executed, leaves them with both legs.
- **Asset:** A8, real funds.
- **Controls:**
  - SPV verification of BTC proofs against header chain
  - Multi-source BtcDataSource quorum
  - Covenant code structurally derived from audited Photonic Wallet patterns
  - 1500+ lines of red-team tests in `test_gravity_red_team.py`
  - README explicit "experimental" flag on covenant variants
- **Residual risk:** Most concentrated risk in the codebase. Audit-recommended target.

### S11: Supply-chain compromise of `coincurve` (TA9)

- **Action:** Malicious `coincurve` release ships with backdoored signing.
- **Asset:** A4, every signature pyrxd produces.
- **Controls:** `pip-audit` in dev deps; `coincurve` is a high-attention package with multiple maintainers. We pin a major-version range, not a specific version.
- **Residual risk:** Catastrophic if exploited. Effective response would require upstream awareness or a security advisory, both of which we'd hear about via standard channels.

### S12: Typosquat of `pyrxd` itself (TA9)

- **Action:** Attacker publishes `py-rxd` or `pyrxd-tools` with malicious code; user installs the wrong package.
- **Asset:** Everything in the user's environment.
- **Control:** None (this is a PyPI registry concern). README links the canonical install path. `[project.urls]` in `pyproject.toml` points to the real repo.
- **Residual risk:** Outside pyrxd's control.

### S13: `--debug` traceback leaks frame locals (TA1, TA2)

- **Action:** User encounters a wallet decrypt failure with `--debug`; traceback is forwarded to a log aggregator that captures stderr; mnemonic local appears in the trace.
- **Asset:** A1.
- **Control:** `errors.CliError.show()` uses `traceback.format_exception(...)` only — never `capture_locals=True`. Source-line context contains variable names but never values. Tested in `test_debug_emits_traceback_on_decrypt_failure`: the user's exact input never appears in `result.output`.
- **Residual risk:** Source line text mentions `mnemonic` and `passphrase` as parameter names; an attacker reading the logs sees the *names* but not values. Acceptable.

### S14: Fee-rate flag set to 0 builds an unmineable tx (TA2)

- **Action:** User passes `--fee-rate 0` (currently rejected by validation) or somehow ends up with effectively-zero fee. Tx is built and broadcast; never confirms; funds appear stuck.
- **Asset:** A4 + A8 (operational, not theft).
- **Control:** `build_send_tx` and `build_send_max_tx` validate `fee_rate > 0`. Default fee rate of 10,000 photons/byte is the documented mainnet relay minimum.
- **Residual risk:** Low — if fee is below relay minimum, the network rejects on broadcast. Funds are not lost; user can rebuild with a higher fee.

### S15: Replay of a signed transaction (general)

- **Action:** Attacker re-broadcasts a signed tx the user already broadcast.
- **Asset:** A8 (already public, same tx confirms once).
- **Control:** Bitcoin/Radiant transactions are inherently non-replayable: they spend specific UTXOs, and once spent those UTXOs are gone. A re-broadcast either confirms the same tx (no-op) or is rejected as conflicting.
- **Residual risk:** None at this layer. Cross-chain Gravity introduces its own replay considerations, addressed by SPV-binding and counterparty-specific covenant params.

### S16: Race condition mid-`save()` corrupts wallet file (TA2 timing)

- **Action:** `wallet new` is interrupted (Ctrl-C, power loss) mid-write.
- **Asset:** A5.
- **Control:** Atomic write pattern: `mkstemp` → `fchmod 0o600` → write → `fsync` → `os.replace`. Either the old file remains intact, or the new fully-fsynced file does. No half-encrypted state.
- **Residual risk:** OS-level filesystem guarantees vary; we trust ext4/xfs/HFS+/APFS to honor `os.replace` atomicity.

### S17: Mnemonic in pytest result.output captured by failing assertion (TA1, hypothetical)

- **Action:** A test asserts on `result.output`, fails for an unrelated reason, pytest's traceback embeds the full output (including the mnemonic) in CI logs.
- **Asset:** A1 (synthetic — test mnemonics are random per run).
- **Control:** Tests use disposable mnemonics. CI logs are private.
- **Residual risk:** Low (synthetic mnemonics never hold real funds). Tracked as [issue #9](https://github.com/Radiant-Core/pyrxd/issues/9).

### S18: Same-uid process abuses the signing agent to spend (TA1) — issue #8

- **Action:** With the agent unlocked (A11), a malicious same-uid process connects to the socket and submits its own `SigningRequest` to drain the wallet. It passes `SO_PEERCRED` (same uid) and the `0600`/`0700` filesystem checks — those gate *other users*, not a co-resident attacker.
- **Asset:** A11 (the unlocked wallet) → A8 (a signed, fund-moving tx).
- **Control (THE control):** **per-spend confirmation.** The agent parses the tx, independently verifies each prevout (C1 — see S19), attributes every output (change re-derived and verified, the rest shown as external payees), and requires a human keypress **on the daemon's own controlling terminal** (`/dev/tty`) before signing — a channel the requesting process cannot drive. A detached daemon with no tty **fails closed** (declines). Small spends below an explicit, opt-in `--auto-confirm-under` threshold skip the prompt; that threshold is documented as outside the trust boundary. The agent **never returns key material** (conformance-tested), so reaching the socket lets an attacker *request* a signature, never *take* the key.
- **Residual risk:** A user who blind-confirms, or who sets a high `--auto-confirm-under`, is unprotected — by their own choice. The confirmation is the boundary; automation of it is out of scope. Idle auto-lock and `agent lock` bound the unlock window.

### S19: Agent tricked into a fee-theft / fund-redirect signature (TA1)

- **Action:** A request lies about an input's prevout value (to burn the surplus to fees) or asks for a non-`ALL|FORKID` sighash (to recombine the signature into a different, fund-redirecting tx), while showing the user a benign-looking spend.
- **Asset:** A4/A11 → A8.
- **Control:** **Prevout authenticity (C1)** — the agent requires the full source tx for each input, verifies it hashes to the input's outpoint, and reads value/script from the *real* prevout (never the request's claim); the displayed summary is derived from the verified tx (display == sign). The agent re-derives the signing key and refuses to sign an input it does not own. **Sighash policy** — v1 signs only `ALL|FORKID`; any other type is refused (it would commit to fewer outputs than the confirmation showed). Partially-owned txs are refused (every input must be attributable).
- **Residual risk:** v1 is P2PKH-only and fully-owned-only by design; multi-party / mixed-owner signing is out of scope.

### S20: Taker offline/censored during `[reveal, t_rxd]` — the R1 free-option residual (TA8)

- **Action:** Maker and taker reach `BOTH_LOCKED`. The maker claims the counter-leg (BTC/ETH), revealing `p` (`SECRET_REVEALED`). The honest taker is then offline, mempool-pinned, or censored across the window from that reveal to `t_rxd`. At `t_rxd` the maker CSV-refunds the Radiant covenant → `ASSET_VULNERABLE` → `ONE_SIDED_LOSS_TAKER` (`swap_state.py`): the taker has paid the counter-leg and the maker holds both legs. This is the inherent HTLC "free option" of the reveal-on-the-long-leg shape.
- **Asset:** the taker's funded counter-leg (A-cross) → maker.
- **Control(s) — what BOUNDS it (it is not eliminated):** the cross-clock timelock margin sizes `t_rxd` to open strictly before the counter-leg deadline minus the finality-stall-tolerant margin; the reorg-finality gate refuses an unsafe early claim (SAFE/WAIT/SQUEEZED, never a silent claim); the **value-scaled claim burial** (red-team 2026-06-12 HIGH, now enforced) requires the taker's claim to bury deep enough that reorging it costs ≥ the value at stake; and the proactive-refund window `N` is coupled to the finality+burial reserve so a reveal cannot be timed into a squeeze the taker could otherwise have acted in.
- **What is NOT a control (correct the record):** the watchtower does **not** autonomously claim the asset. On a `SAFE` gate it emits a `PAGE_CLAIM` **alert** (a display string + deadline) and **broadcasts nothing** — there is no `ClaimExecutor` in v1 (only `RefundExecutor`, which re-broadcasts an operator-pre-signed BTC refund and never touches `p`). So R1's closure rests on **operator/taker liveness within `t_rxd`** (respond to the page, claim before the deadline), not on automation. Any description of "watchtower auto-claim" as the R1 mitigation is wrong against the code.
- **Residual risk:** REAL and ACCEPTED (same as the BTC↔RXD direction) — this is the inherent HTLC free option, not a pyrxd bug. Surfaced loudly (never a silent `COMPLETED`). Closing it autonomously is a deferred reorg-gated claim executor (`watch/README.md` "Remaining"); until then, size `t_rxd` for the worst-case pin/eviction window the taker must survive online.

## Controls in place

Cross-reference of controls and the threats they address:

| Control | Threats addressed | Code location |
|---------|-------------------|---------------|
| AES-256-GCM wallet encryption | S4, S5 | `src/pyrxd/hd/wallet.py:save/load` |
| scrypt KDF (n=2^14) | S4 | `src/pyrxd/hd/wallet.py:_derive_enc_key` |
| Mode 0o600 enforcement (save) | S1, S5 | `src/pyrxd/hd/wallet.py:save` (mkstemp + fchmod) |
| Mode 0o600 verification (load) | S5 | `src/pyrxd/hd/wallet.py:_load_existing` |
| Atomic write (mkstemp + replace) | S16 | `src/pyrxd/hd/wallet.py:save` |
| `SecretBytes` repr/copy/pickle disable | TA1 (post-compromise mitigation) | `src/pyrxd/security/secrets.py` |
| `SecretBytes.zeroize()` | TA1 (best-effort) | `src/pyrxd/security/secrets.py:zeroize` |
| `__hash__ = None` on key types | TA1 (no dict/set leakage) | `src/pyrxd/keys.py`, `src/pyrxd/security/secrets.py`, `src/pyrxd/hd/bip32.py` |
| `hmac.compare_digest` for key equality | side-channel timing | `src/pyrxd/keys.py:PrivateKey.__eq__`, `src/pyrxd/security/secrets.py:SecretBytes.__eq__` |
| RFC 6979 deterministic signatures | TA1 (no nonce reuse) | via `coincurve` |
| Low-s normalization | tx malleability | via `coincurve` |
| `wss://` enforced; `ws://` rejected | TA3, TA4 | `src/pyrxd/network/electrumx.py` URL validation |
| Response size cap (10 MB) | TA5 (memory DoS) | `src/pyrxd/network/electrumx.py`, `src/pyrxd/network/bitcoin.py` |
| Per-id JSON-RPC correlation | TA5 (response-swap race) | `src/pyrxd/network/electrumx.py:_pending` |
| Typed boundary validation (Hex32, Txid, etc.) | input validation everywhere | `src/pyrxd/security/types.py` |
| Mnemonic input via `click.prompt(hide_input=True)` | TA2 (echo prevention) | `src/pyrxd/cli/prompts.py` |
| Mnemonic display Enter gate | TA2 | `src/pyrxd/cli/prompts.py:show_mnemonic` |
| Mnemonic normalization before BIP39 validation | TA2 | `src/pyrxd/cli/prompts.py:_normalize_mnemonic` |
| `--json --yes` required for destructive ops | TA2 (footgun in scripts) | `src/pyrxd/cli/context.py:is_destructive_mode_safe` |
| Confirmation summary before broadcast | TA2, TA7 | `src/pyrxd/cli/glyph_cmds.py:_confirm_or_abort` |
| `--debug` traceback without `capture_locals` | S13 | `src/pyrxd/cli/errors.py:CliError.show` |
| Static "decrypt failed" message | TA1 (no input echo) | `src/pyrxd/hd/wallet.py:_load_existing`, CLI surface |
| Wallet save refuses overwrite | TA2 | `src/pyrxd/cli/wallet_cmds.py:wallet_new` |
| Library N5 fix: re-raise NetworkError on scan | S9 | `src/pyrxd/hd/wallet.py:_scan_chain` |
| Library N6 fix: load() raises FileNotFoundError | TA2 (no silent overwrite) | `src/pyrxd/hd/wallet.py:load` |
| Two-pass fee with unlock-script reset | S6 | `src/pyrxd/wallet.py`, `src/pyrxd/hd/wallet.py:build_send_tx` |
| Multi-source data quorum (detects source *disagreement*, NOT a self-consistent forgery) | TA6 | `src/pyrxd/network/bitcoin.py:MultiSourceBtcDataSource` |
| Committed nBits pin enforced in the SPV verifier (the actual forgery defense) | TA6 | `src/pyrxd/spv/chain.py:verify_chain`, `proof.py:CovenantParams.expected_nbits` |
| Merkle proof bound to the height-identified header | TA6 | `src/pyrxd/spv/proof.py:build(tx_block_height=…)` |
| Confirmation-depth `[1,tip]` floor + above-dust funding quorum | TA6 | `src/pyrxd/network/bitcoin.py:get_raw_tx`, `MultiSourceBtcFundingReader` |
| Sole-authority audit gate (covenant-less use fails closed) | TA6 | `src/pyrxd/spv/proof.py:require_spv_sole_authority_cleared` |
| SPV verification (Gravity) | TA6, TA8 | `src/pyrxd/spv/`, `src/pyrxd/gravity/` |
| Gravity red-team test suite | TA8 | `tests/test_gravity_red_team.py` (1500+ lines) |
| Agent per-spend confirmation on `/dev/tty`, threshold 0 = always confirm incl. self-spends (fails closed w/o tty; utf-8) | S18 | `src/pyrxd/agent/confirm.py`, `signer.py` |
| Agent refuses unattributable outputs (non-P2PKH/non-OP_RETURN) so the user always sees a verifiable destination | S18 | `src/pyrxd/agent/signer.py:_summarize` |
| Agent bounds attacker-supplied derivation coords (change∈{0,1}, index≤cap) before any key derivation | S18 (pre-confirm DoS) | `src/pyrxd/agent/signer.py:_check_coords` |
| Agent prevout authenticity (source-tx verified, value/script from real prevout) | S19 | `src/pyrxd/agent/signer.py:_verify_and_prepare_input` |
| Agent `ALL\|FORKID`-only sighash + fully-owned-only | S19 | `src/pyrxd/agent/signer.py` |
| Agent never returns key material (conformance-tested) | S18 | `src/pyrxd/agent/signer.py`, `tests/test_agent_signer.py` |
| Agent socket: `0700` dir + `0600` socket + `SO_PEERCRED` uid==owner; per-conn recv timeout (anti-slow-loris) | TA1 (other-uid) | `src/pyrxd/agent/daemon.py:_bind/_read_peer_uid/_serve_conn` |
| Agent lock scrubs the seed (the only long-lived secret — the account xprv is re-derived transiently, never stored, #8/H1) and fails the derivation seam closed; idle auto-lock + on-demand `lock` + SIGTERM/SIGHUP/atexit | A11 window | `src/pyrxd/agent/daemon.py:lock`, `hd/wallet.py:zeroize`/`_xprv`, `cli/agent_cmds.py` |
| Agent process hygiene (mlock, PR_SET_DUMPABLE 0, no core dumps; best-effort) | A11 residency | `src/pyrxd/agent/hygiene.py` |
| CodeQL on every push | static analysis | `.github/workflows/codeql.yml` |
| Bandit on every push | security smells | `.github/workflows/ci.yml` |
| ruff lint + format | code hygiene | `.github/workflows/lint.yml` |
| `pip-audit` (dev dep) | known-CVE supply-chain | `pyproject.toml` |
| detect-secrets pre-commit | committed-secret prevention | `.pre-commit-config.yaml` |
| 100% coverage on `pyrxd.security` | ensures security primitives are exercised | CI coverage gate |
| 85% overall coverage | structural confidence | CI coverage gate |

## Known gaps

Honest list. These are not vulnerabilities; they're places where pyrxd's defense ends.

### Crypto / library

1. **No third-party crypto audit** of pyrxd's integration of underlying primitives.
2. **No formal verification of BIP32/39/44 vectors** beyond unit tests. Test vectors come from the BIP specs themselves.
3. **No fuzz testing of the CLI surface.** [Issue #10.](https://github.com/Radiant-Core/pyrxd/issues/10)
4. **No timing-attack analysis** of pyrxd-internal comparisons beyond known-good `hmac.compare_digest` use.
5. **Memory zeroization is best-effort** — CPython does not guarantee secure memory. The signing agent's only resident **long-lived** secret is the seed (a `SecretBytes`), which IS `memset` on lock. The account xprv is **no longer stored long-lived** (hardening #8/H1): `HdWallet._xprv` is now a property that re-derives the account key from the seed per operation, so on lock the seed is scrubbed and the property fails closed — there is no persistent xprv copy to leak across the unlock window. The residual is now only the **transient** per-operation copy: while a signature is actively being produced, an account xprv / libsecp256k1 key necessarily exists in memory for that moment (you cannot sign without the key), and CPython cannot overwrite those immutable/C copies in place before GC. Their residency until the pages are reused is bounded by the agent's best-effort process hygiene (`mlock`/`PR_SET_DUMPABLE 0`/no core dumps), not a guaranteed erase — do not over-state it as "erased". This is the irreducible floor (the key must be usable to sign), not a design gap.

### Network

6. **Single-source RXD reads (accepted assumption, stated for the auditor).** Three RXD-side reads trust a single source by design: (a) the default single **ElectrumX** endpoint for plain-RXD wallet ops (TA5 has unmitigated reach here — multi-source ElectrumX is not implemented; only the Bitcoin data sources have quorum); (b) the single **RXinDexer** that resolves Glyph reads and backs the Gravity REF-authenticity gate (`verify_ref_authenticity`); (c) single-source RXD funding depth (a SPOF accepted only for dust). This is an **accepted assumption, not a missing control**: a *self-consistent* lie is byte-identical from every source, so adding a 2nd source — which only detects *disagreement* — has bounded value while the operating cost is real. The load-bearing defenses are the on-chain covenant pins (nBits / `expectedNBits`, the REF-uniqueness consensus rule), not read-side quorum. Standing up a 2nd independent RXD source is the right hardening **at first non-dust real value**; it is documented here so the audit reviews a stated single-source boundary up front rather than discovering it.
7. **No certificate pinning for ElectrumX TLS.** A CA compromise enables TA4. We rely on system trust store.
8. **The SPV primitive is not a self-sufficient sole authority.** It enforces the committed nBits pin and per-header PoW but does **not** do most-cumulative-work selection or independent network-difficulty oracling (audit F-01). It is safe only behind an on-chain covenant pinning nBits; any covenant-less use (bridge-in/oracle/gate) fails closed via `require_spv_sole_authority_cleared` pending external audit. See [`docs/how-to/spv-verification-pitfalls.md`](docs/how-to/spv-verification-pitfalls.md).

### CLI

9. **Broadcast summary doesn't show resolved `owner_pkh` from metadata files.** S7 residual risk. **Should be addressed before v0.3.0 release.**
10. **No clipboard hygiene warning.** S3 residual risk. [Issue #11.](https://github.com/Radiant-Core/pyrxd/issues/11)
11. **Mnemonic re-entry per command** is mitigated by the optional `pyrxd agent` (issue #8, Path A′): a sign-on-behalf daemon holds the wallet for an unlock window so the mnemonic is typed once, and the key is removed from the short-lived CLI process entirely (the daemon signs). Residual: while unlocked, a same-uid process can *request* signatures — gated by per-spend confirmation (S18), never by taking the key. The agent is **opt-in**; with it off, the per-command prompt (and its S2/S3 residual risk) remains the default. The agent has not had a third-party audit (gap #1 applies).

### Protocol

12. **Gravity covenant variants flagged "still being hardened"** in README. TA8 is the highest-stakes attacker; this is the highest-priority audit target.
13. **dMint V1 deploy + PoW mint: now regtest-consensus-validated.** The earlier "documented but not implemented" wording was stale — the builders + reference miner shipped; the real gap was node validation. `tests/test_dmint_v1_regtest_e2e.py` proves on a real `radiant-core` node that a pyrxd-built V1 deploy (commit→reveal genesis) and a PoW-mined mint are accepted, a wrong nonce is rejected, and the contract recreates at height+1. Surfaced a consensus requirement the golden vectors missed: V1 contracts MUST be 1-photon singletons (covenant enforces `OP_OUTPUTVALUE==1`); `build_dmint_mint_tx` now rejects non-1 carriers early. **dMint V2 is now consensus-validated too (#219):** the canonical-Photonic redesign is byte-matched to upstream and accepted on `radiant-core` v3.1.1 regtest (FIXED + LWMA, with on-chain difficulty advancement) AND Radiant mainnet 3.1.2: the first V2 FIXED deploy + PoW mint confirmed on mainnet (deploy `95335028…bb16fb09`, mint `1239f64a…e0cd6c67`), plus an LWMA mint that lowered the recreated target on-chain (MAX → ~MAX/8) exactly matching the off-chain DAA (deploy `dea3beb9…`, mint `e7b52f16…`) — so adaptive difficulty is proven on mainnet, not just regtest. The per-call `V2UnvalidatedWarning` is no longer emitted; V2 deploys stay behind `allow_v2_deploy=True` as an explicit opt-in for the newer format. All five DAA modes are now ported and byte-matched to canonical Photonic, and the `glyph deploy-dmint --v2` / `claim-dmint` CLI verbs expose V2 deploy + PoW mint. **EPOCH int64-overflow: found, fixed upstream, re-enabled.** Differential testing of the ported modes surfaced an int64-overflow in the *canonical Photonic* EPOCH (and LWMA) bytecode — the on-chain retarget computed `target × clampedDelta` (multiply-first, output capped at `MAX_TARGET` not `2^48`), which exceeds int64 (`CScriptNum`) for ordinary parameters and aborts the mint with `INVALID_NUMBER_RANGE_64_BIT` (`OP_MUL → safeMul`), permanently bricking the contract (a liveness bug, not a theft vector — confirmed against `radiant-core` `interpreter.cpp`). EPOCH was temporarily refused at deploy while the canonical bytecode was broken; the fix is now **merged upstream** ([`Radiant-Core/Photonic-Wallet#2`](https://github.com/Radiant-Core/Photonic-Wallet/pull/2) — EPOCH clamps the target to `EPOCH_MAX_SAFE_TARGET` (2^48) on *both* sides of the multiply and divides first, so the intermediate stays ≤ 2^52 for any reachable state; LWMA floors `timeDelta` at 0 via `OP_0 OP_MAX`). pyrxd **byte-matches the merged canonical** (EPOCH+LWMA golden vectors regenerated; the off-chain miner replicas `compute_next_target_epoch`/`_linear` updated to match), and `DmintV2DeployParams` / the CLI now accept `DaaMode.EPOCH` again (difficulty ≥ 32768 for the 2^48 cap). The off-chain `current_time` validation (reject backwards/post-2038 locktimes before grinding) is retained as defence-in-depth. Residual: this newer surface is unaudited — verify it yourself before moving real value.
14. **No multi-signature support.** Single-sig only; users wanting m-of-n must build it themselves.

### Supply chain

15. **No pinned transitive dependency hashes.** A compromised release of `coincurve`, `Cryptodome`, etc. would propagate. `pip-audit` catches known CVEs but not zero-days. (Deliberate for a *library* — pinning transitive hashes over-constrains downstreams.)
16. **SBOM now generated.** Each GitHub Release attaches a CycloneDX SBOM (`pyrxd-<version>.cdx.json`) built from the resolved dependency tree by the publish workflow (`.github/workflows/publish.yml`).
17. **Release artifacts now carry PEP 740 attestations.** PyPI 2FA + OIDC Trusted Publishing are on, and the publish action emits per-artifact Sigstore digital attestations (verifiable on the PyPI project page). A gpg-signed git tag / GitHub Release signature is still optional and not set up.

### Process

18. **Incident-response runbook now exists.** [`docs/runbooks/incident-response.md`](docs/runbooks/incident-response.md) documents the triage → fix-branch → GitHub Security Advisory / CVE → release → notify flow for a report to `security@mudwoodlabs.com`.
19. ~~No coordinated-disclosure SLA.~~ **Resolved:** Part I above states the SLA — acknowledge within 2 business days, initial assessment within 7, coordinated disclosure typically within 90 (Project Zero norms).
20. **No external eyes.** Solo developer; nothing has been reviewed by anyone else. An independent audit is the natural next step before relying on the swap stack for non-dust real value — verify it yourself until then.

## Out of scope (explicit non-coverage)

We do not protect against:

- Coercion / wrench attacks
- Physical access to an unlocked machine
- Compromised OS, firmware, BIOS, hypervisor
- Side channels at the silicon level
- Quantum computers (secp256k1 is not post-quantum safe; no chain currently is)
- User running the wrong binary (typosquats, malicious forks)
- User leaking the mnemonic via channels pyrxd doesn't see (photographing it, reading it aloud on a podcast, etc.)
- User running pyrxd in a hostile container that can read process memory
- Future Radiant consensus bugs that invalidate the protocol pyrxd implements

## For auditors and security researchers

> Part III below (the external security audit scoping brief) pulls the in-scope
> module map, the load-bearing assumptions, the fail-closed opt-in gates, and the **complete
> stable-ID residual register** (this doc's scenarios *plus* the design-note and in-code residuals)
> into one place — start there for a commissioned audit.

If you have time and skill to look at pyrxd, here's where to start, ranked by expected return on investigation:

1. **Gravity covenant code** (`src/pyrxd/gravity/`) — highest stakes, most complex protocol code. Review focus: SPV proof construction, covenant param validation, sighash flag handling, edge cases in `tests/test_gravity_red_team.py` that document known concerns.
2. **Wallet file format and load path** (`src/pyrxd/hd/wallet.py:save/load`) — second-highest stakes (key material). Review focus: AEAD construction, mode-bit checks, malformed-JSON guards, the edge between "file decrypts" and "file is structurally valid wallet."
3. **Glyph script construction** (`src/pyrxd/glyph/`) — lower direct stakes (most attacks here are footguns, not theft) but the metadata-trust issue (S7) is real. Review focus: how `owner_pkh` propagates from CBOR to scriptPubKey to broadcast, and what the user actually sees before signing.
4. **CLI mnemonic handling** (`src/pyrxd/cli/wallet_cmds.py`, `src/pyrxd/cli/prompts.py`) — boring but easy to mess up. Review focus: every code path that touches the mnemonic string, and confirmation that none of them log, copy to dict-keyed structures, or serialize without `SecretBytes`.
5. **Network response parsing** (`src/pyrxd/network/electrumx.py`, `src/pyrxd/network/bitcoin.py`) — not where private keys live but where lying-server defenses live. Review focus: hex decoding, length checks, content-type validation, response-correlation race window.

If you find something, please report privately to `security@mudwoodlabs.com`. We don't pay bounties yet but credit researchers in this file and in the changelog.

## Revision history

- **2026-06-15** — fixed the duplicate gap-`#8` numbering: the "Known gaps" list now runs `1–20` uniquely (the CLI `owner_pkh` gap moved `8→9` and the tail shifted `+1`). Added the consolidated security audit scoping brief (stable residual IDs across this doc, the design notes, and in-code residuals).
- **2026-05-01** v1.0 — initial threat model. Documents v0.3 surface (library + CLI + glyph commands).

---

# Part III — External Security Audit Scoping Brief

**Status:** draft for commission · **Frozen commit:** _pin at commission time_ (do **not**
audit a moving `main`) · **Companion docs:** [`docs/concepts/architecture.md`](docs/concepts/architecture.md).

This brief tells an external auditor **what to audit, what is deliberately out of scope, the
assumptions the code is allowed to make, and the complete register of accepted/known residual
risks** — consolidated from the threat model, the design-decision notes, and the in-code
residual notes so the audit reviews a *stated* boundary rather than rediscovering it. pyrxd is
open-source software, provided as-is under the [LICENSE](LICENSE); the cross-chain swap stack
is **unaudited**, and this brief is the deliverable that lets an independent review certify it.
The code defaults the swap legs to test networks via `require_audit_cleared` (a fail-closed
opt-in), so an audit's sign-off is the natural trigger to set `audit_cleared=True` for mainnet.

## 0. How to use this brief

- Residuals carry **stable IDs** (e.g. `SWAP-R1`, `CAPFEE-ISOLATION`). Where a residual already
  had a legacy id (a threat-model `S#`/gap `#n`, or an in-code tag like `SEEN-1`, `MEDIUM-1`,
  `R1`, `F-01`), the legacy id is noted — the legacy numbering has known collisions (see §7).
- **Severity** is the *pre-mitigation* class; **Status** is `open` / `mitigated` (a control
  exists) / `accepted` (a conscious residual) / `deferred` (a feature not built) / `gate` (a
  fail-closed opt-in that defaults the risk off until consciously enabled).
- Start at §5 (priority targets) for where the return-on-review is highest.

## 1. Scope — what to audit

The audit-critical surface (ranked; full per-module rationale in
[`docs/concepts/architecture.md`](docs/concepts/architecture.md)):

| Area | Modules | Why critical |
|---|---|---|
| **Cross-chain swap covenant** | `src/pyrxd/gravity/` — `htlc_covenant.py`, `htlc_spend.py`, `radiant_leg.py`, `swap_coordinator.py`, `ref_authenticity.py`, `capped_fee_source.py`, `seen_store.py` | The single most adversarial setting (hostile counterparty wants both legs). Covenant build/spend, the role/timelock invariant, the REF-authenticity gate, the fee-key trust boundary. |
| **BTC + ETH counter-legs** | `src/pyrxd/btc_wallet/` (`htlc_leg.py`, `taproot.py`, `chains.py`), `src/pyrxd/eth_wallet/` (`chains.py`, `locator.py`), `src/pyrxd/gravity/eth_leg.py` | The Taproot-HTLC + Solidity-HTLC legs, the `require_audit_cleared` gate + `AUDIT_CLEARED_NETWORKS`, the per-chain finality/block-interval safety knobs. |
| **Watchtower** | `src/pyrxd/gravity/watch/` — `decide.py`, `reconciler.py`, `quorum.py`, `executor.py`, `adapters.py`, `eth_adapters.py`, `alerts.py`, `heartbeat.py` | Alert-only v1 + the dormant, dust-capped, keyless v2 BTC refund. `executor.py` is the **only** component that broadcasts. |
| **SPV verification** | `src/pyrxd/spv/` — `chain.py`, `proof.py`, `pow.py`, `merkle.py`, `payment.py` | One-way Bitcoin-proof verifier that gates covenant release. The nBits-pin-before-PoW defense + `require_spv_sole_authority_cleared`. |
| **Key material** | `src/pyrxd/hd/wallet.py`, `src/pyrxd/security/` (`secrets.py`, `types.py`), `src/pyrxd/keys.py`, `src/pyrxd/hd/bip32.py` | AES-256-GCM + scrypt wallet; `SecretBytes`; the agent's transient-xprv re-derivation; coin-type derivation. |
| **Signing agent** | `src/pyrxd/agent/` — `signer.py`, `confirm.py`, `daemon.py`, `hygiene.py` | The unlocked-wallet daemon (A11) on a `0600` socket; per-spend `/dev/tty` confirmation; prevout authenticity. |
| **Glyph / metadata / dMint** | `src/pyrxd/glyph/` — `script.py`, `dmint.py`, `dmint/chain.py`, metadata→scriptPubKey path | Attacker-facing parser surface + the hostile-metadata `owner_pkh` trust path. |
| **Lying-server defenses** | `src/pyrxd/network/electrumx.py`, `src/pyrxd/network/bitcoin.py` | `wss`-only, response caps, per-id correlation, the multi-source BTC quorum. |

Part I above (§Scope) lists the in-scope packages for *reports* (`pyrxd.curve|security|aes_cbc|crypto`,
`pyrxd.hd`, `pyrxd.transaction|script`, `pyrxd.glyph`, `pyrxd.gravity`, `pyrxd.network`).

## 2. Out of scope

From the threat model's non-goals + Part I §Scope: coercion / $5-wrench, physical access to an
unlocked machine, compromised OS/firmware/hypervisor, silicon side-channels, quantum (secp256k1
is not PQ-safe), typosquats / wrong-binary, the user leaking the mnemonic through channels pyrxd
can't see, dependency vulnerabilities (report upstream), and future Radiant consensus bugs.
**Single-sig only** (no multisig). **The deprecated SPV-oracle *swap* covenant is out of scope**
(superseded by the HTLC swap; see `SWAP-SPV-R2`/`-FORGED`).

## 3. Load-bearing assumptions (stated up front)

The audit should accept or challenge these explicitly — the code's safety arguments rest on them.

- **`ASSUME-SINGLE-SOURCE` (gap #6).** Three RXD-side reads trust a single source by design:
  (a) the default single ElectrumX endpoint for plain-RXD wallet ops; (b) the single RXinDexer
  that resolves Glyph reads and backs `verify_ref_authenticity`; (c) single-source RXD funding
  depth (dust only). Rationale: a *self-consistent* lie is byte-identical from every source, so a
  2nd source — which only detects *disagreement* — has bounded value; the load-bearing defenses
  are the on-chain covenant pins (nBits, the REF-uniqueness consensus rule), not read-side quorum.
  Standing up a 2nd independent RXD source is the right hardening **at first non-dust real value**.
- **`ASSUME-CAPFEE-ISOLATION`.** `CappedFeeWalletSource`'s structural ceiling is real **only if**
  the operator funds it from a key isolated from the main wallet (the class validates P2PKH +
  wif-control + the cap, but cannot verify key isolation). See `CAPFEE-ISOLATION`.
- **`ASSUME-PRE-AUDIT-GATE`.** The HTLC swap defaults to test networks via `require_audit_cleared`
  (`AUDIT_CLEARED_NETWORKS = {bcrt, regtest, tb, signet, rltc, tltc}`), and covenant-less SPV
  value-release defaults off via `require_spv_sole_authority_cleared`. Both are advisory
  fail-closed opt-ins — mainnet use requires consciously setting the opt-in.
- **`ASSUME-WATCH-ALERT-ONLY`.** The watchtower core is **alert-only and keyless**; it never
  touches the preimage `p`. The sole autonomous action (v2 BTC refund) is dormant-by-construction
  + dust-capped (10 000 sats). R1's closure therefore rests on **taker/operator liveness within
  `t_rxd`**, not on automation — any "watchtower auto-claim" description is wrong against the code.

## 4. Fail-closed opt-in gates

The code defaults value-bearing operation off unless an explicit opt-in is set — these are the
seams an audit would certify before they are enabled:

| Gate | Defaults off | Where |
|---|---|---|
| `require_audit_cleared` / `AUDIT_CLEARED_NETWORKS` | any mainnet swap leg | `btc_wallet/htlc_leg.py`, `gravity/radiant_leg.py` |
| `require_spv_sole_authority_cleared` | covenant-less SPV value-release | `spv/proof.py` |
| `require_measured` margins (`MEDIUM-1`) | a real-value ETH swap on *estimated* margins | `gravity/swap_coordinator.py` |
| value-scaled claim burial vs `accept_flat_burial` | a non-dust swap reorg-reversible at flat burial | `gravity/swap_coordinator.py` |
| durable seen-store default (was `accept_nondurable_seen`) | replay/free-option window across restart | `gravity/seen_store.py`, value harnesses |

## 5. Priority targets (ranked by expected return)

1. **`gravity/` covenant + spend + REF gate** — highest stakes, most complex. Focus: covenant
   param binding, sighash handling, the `R1` fake-singleton defense (`SWAP-R1`), the timelock /
   role invariant (`SWAP-TIMELOCK-INVARIANT`, `SWAP-MAKER-STALL`), value-scaled burial.
2. **`hd/wallet.py` save/load + the agent** — key material; the transient-xprv re-derivation
   (`AGENT-SAMEUID`/H1) and prevout authenticity (`AGENT-REDIRECT`/C1).
3. **`spv/`** — the nBits-pin-before-PoW forgery defense and `SPV-SOLE-AUTHORITY` (F-01).
4. **`glyph/` parser + metadata path** — the attacker-facing parser surface (un-fuzzed) and the
   `owner_pkh` trust path (`GLYPH-OWNERPKH`/S7).
5. **`gravity/watch/`** — alert correctness, the co-fire `hold-that-loses` residual, and the
   dormant autonomy gate before any future arming.

## 6. Residual register (consolidated, stable IDs)

Every accepted/known residual, deduplicated across the threat model, design notes, and code.
`(TM S#/gap#)` = also in the threat model; otherwise the residual lives only in a design note or
code docstring (the brief's value-add — these would otherwise be missed).

### 6.1 Swap / covenant
| ID | Sev | Status | Residual | Where / legacy id |
|---|---|---|---|---|
| `SWAP-R1` | critical | mitigated (gate) | Consensus enforces ref **uniqueness**, not **provenance** — a fake-singleton covenant is consensus-valid; `verify_ref_authenticity` is the *only* defense | `gravity/ref_authenticity.py` · R1 |
| `SWAP-COVENANT-BUGS` | critical | open | Gravity covenant variants "still being hardened" — the most concentrated risk in the codebase | TM S10 / gap #12 |
| `SWAP-FREEOPT` | high | accepted | Taker offline/censored across `[reveal, t_rxd]` → one-sided loss (HTLC free option). Bounded by margin + reorg gate + value-scaled burial; **not** eliminated | TM S20 / R1 |
| `SWAP-TIMELOCK-INVARIANT` | high | mitigated | `t_counter > t_rxd + margin` is client-enforced (`assert_timelock_margin`); a wrong client could route around it | `swap_coordinator.py` |
| `SWAP-MAKER-STALL` | high | mitigated | A stalling maker can take both legs unless the taker stops waiting / refunds proactively (C1) | `swap_coordinator.py` |
| `SWAP-BURIAL` | high | mitigated | Flat claim-burial bounds reorg *probability*, not reorg *cost vs value* (low-cap PoW); value-scaled burial now enforced | `swap_coordinator.py` · red-team 2026-06-12 HIGH |
| `SWAP-MARGIN-MEASURED` | high | gate | Default cross-chain margin is **estimated**; a real-value swap must use `MarginPolicy.measured(...)` | `swap_coordinator.py` |
| `SWAP-SEEN1` | high | mitigated | Non-durable seen-store loses H-freshness across restart/2nd process; durable SQLite store is now the harness default | `gravity/seen_store.py` · SEEN-1 |
| `SWAP-ETH-MARGIN` | medium | gate | Value-bearing ETH swap on estimated margins disables two ETH defenses unless consciously opted in | `swap_coordinator.py` · MEDIUM-1 |
| `SWAP-ETH-DEPLOY-VERIFY` | medium | mitigated | `EthLeg.verify_funded` necessarily runs *after* value is on-chain (no pre-image of funding) | `gravity/eth_leg.py` |

### 6.2 Capped fee source (autonomy trust boundary)
| ID | Sev | Status | Residual | Where |
|---|---|---|---|---|
| `CAPFEE-ISOLATION` | high | accepted | The structural ceiling holds only if the pool key is isolated from the main wallet — the class cannot verify this | `capped_fee_source.py` |
| `CAPFEE-TYPE-GATE` | high | open | `RadiantCovenantLeg`'s `FeeUtxoSource` gate can't distinguish capped from uncapped — future autonomous wiring **must** assert the concrete type | `radiant_leg.py` |
| `CAPFEE-MANUAL-REFILL` | medium | accepted | Pool refill must be a manual, audited op — never an auto top-up from the main wallet | `capped_fee_source.py` |
| `CAPFEE-FAILCLOSED-CALLER` | medium | accepted | The caller must treat `FeePoolExhaustedError` as fail-closed (no uncapped fallback) | `capped_fee_source.py` |

### 6.3 Watchtower
| ID | Sev | Status | Residual | Where |
|---|---|---|---|---|
| `WATCH-AUTONOMY-GATE` | high | deferred | Autonomy beyond dust is audit-gated; the v2 BTC refund is dormant-by-construction + dust-capped | `watch/executor.py` |
| `WATCH-TWO-PARTY` | high | open | No genuine two-party adversarial run — every run so far is single-operator (plumbing proof, not adversarial proof) | `watch/README.md` |
| `WATCH-COFIRE` | medium | accepted | Below-quorum-inside-window can co-fire claim+refund into a "hold-that-loses" (accepted: hold + CRITICAL operator fallback) | `watch/README.md` |
| `WATCH-ETH-SINGLESRC` | medium | open | Single-source ETH detection/finality (no ETH quorum) — can *delay* a page, never lose one | `watch/eth_adapters.py` |
| `WATCH-ETH-NOEVENT` | medium | accepted | An ETH HTLC that emits no event on `claim()` is undetectable by the tower | `watch/eth_adapters.py` |
| `WATCH-SEENSTORE-DUR` | low | open | Watchtower dedup / SeenStore durability across restarts | `watch/README.md` |
| `WATCH-STALLTRACKER` | low | open | `FinalityStallTracker` not wired into the live tower (point-in-time ETH finality only) | `watch/` |

### 6.4 SPV
| ID | Sev | Status | Residual | Where / legacy |
|---|---|---|---|---|
| `SPV-SOLE-AUTHORITY` | high | mitigated (gate) | No most-cumulative-work selection / difficulty oracle; safe only behind a covenant nBits pin (`require_spv_sole_authority_cleared`) | `spv/chain.py`, `proof.py` · F-01 / TM gap #8 |
| `SPV-DIFFICULTY-FLOOR` | high | accepted | Offer-time difficulty floor + most-work selection deferred to the covenant pin | `spv/` · pitfalls how-to |
| `SPV-SINGLESOURCE-DEPTH` | medium | accepted | Single-source confirmation depth gated to low value; quorum only detects disagreement | `network/bitcoin.py` |
| `SPV-SWAP-R2` | medium | accepted | Deprecated SPV-oracle *swap* covenant accepts `scriptSig ≥ 128 B` (taker-fund-loss footgun) — won't-fix on the retired path | spv-swap-deprecated note · R2 |
| `SPV-SWAP-FORGED` | medium | accepted | Forged-payment-in-scriptSig in the deprecated swap parser — won't-fix on the retired path | spv-swap-deprecated note |

### 6.5 REF gate / indexer / network
| ID | Sev | Status | Residual | Where / legacy |
|---|---|---|---|---|
| `NET-SINGLE-SOURCE` | medium | accepted | Single-source RXD/REF reads (= `ASSUME-SINGLE-SOURCE`) | TM gap #6 |
| `REFGATE-TRANSPORT-PARITY` | high | mitigated | The REF gate's fail-closed property must hold across **both** the ElectrumX and the REST transports | `radiant_leg.py`, REST adapter |
| `REFGATE-SOURCE-SKEW` | medium | accepted | RXinDexer REST field/shape drift is brittle (fail-closed on drift) | REST REF adapter |
| `NET-ELECTRUMX-HISTORY` | low | open | A *consistently* lying ElectrumX can hide address history (privacy); multi-source ElectrumX not implemented | TM S9 |
| `NET-UTXO-VALUE` | low | accepted | A lying ElectrumX UTXO value → fee overpay / invalid tx (network-rejected), never direct theft | TM S8 |
| `NET-TLS-PINNING` | medium | open | No certificate pinning for ElectrumX TLS (CA-compromise → TA4) | TM gap #7 |

### 6.6 Key material / wallet / agent
| ID | Sev | Status | Residual | Where / legacy |
|---|---|---|---|---|
| `KEY-SCROLLBACK` | high | accepted | Mnemonic in terminal scrollback — cannot clear portably | TM S2 |
| `AGENT-SAMEUID` | high | mitigated | Same-uid process abuses the unlocked agent — bounded by per-spend `/dev/tty` confirmation; the agent never returns key material | TM S18 / issue #8 / H1 |
| `KEY-COINTYPE-LOAD` | high | open | Wallet load path does not validate persisted `coin_type` against the active default — a silent flip could derive a wrong key | `hd/wallet.py`, `constants.py` |
| `KEY-CLIPBOARD` | medium | open | No clipboard-hygiene warning after mnemonic display | TM S3 / gap #10 / issue #11 |
| `KEY-JSON-REDIRECT` | medium | accepted | `wallet new --json --yes \| tee` lands the mnemonic unencrypted — documentation, not enforcement | TM S1 |
| `AGENT-REDIRECT` | medium | mitigated | Agent tricked into fee-theft/redirect signature — bounded by prevout authenticity (C1) + `ALL\|FORKID`-only | TM S19 |
| `KEY-COINTYPE-DOWNGRADE` | medium | accepted | NEW→OLD→NEW coin-type downgrade can corrupt persisted `coin_type` | coin-type design note |
| `KEY-ZEROIZE` | low | accepted | Best-effort zeroization; the transient signing-key copy is irreducible (key must exist to sign) | TM gap #5 |
| `KEY-BRUTEFORCE` | low | mitigated | Offline brute-force of a leaked `wallet.dat` — scrypt n=2^14 + per-file salt + GCM tag | TM S4 |
| `KEY-WORLDREADABLE` | low | mitigated | World-readable `wallet.dat` post-restore — load-time mode check (POSIX only) | TM S5 |

### 6.7 Glyph / metadata / dMint
| ID | Sev | Status | Residual | Where / legacy |
|---|---|---|---|---|
| `GLYPH-OWNERPKH` | high | open | Broadcast summary doesn't surface the resolved `owner_pkh` from a metadata file (hostile-metadata substitution) | TM S7 / gap #9 |
| `GLYPH-PARSER-FUZZ` | medium | open | Attacker-facing parser surface not yet fuzzed (hypothesis stage planned) | TM gap #3 / issue #10 |
| `GLYPH-DUAL-WALKER` | medium | open | Phantom-ref risk: two divergent opcode walkers can drift on reserved bytes | FT-covenant note |
| `DMINT-V2-GOLDEN` | medium | open | No mainnet golden vectors for V2 dMint / FT transfer / NFT mint | dMint notes |
| `DMINT-V2-UNVALIDATED` | low | open | V2 dMint contracts unvalidated (`V2UnvalidatedWarning`); no CLI verb yet | TM gap #13 |

### 6.8 Supply chain / process / deferred
| ID | Sev | Status | Residual | Where / legacy |
|---|---|---|---|---|
| `PROC-NO-AUDIT` | high | open | No external eyes — solo developer; an independent review is the natural next step for the swap stack (this brief scopes it) | TM gap #1 / #20 |
| `SUPPLY-COINCURVE` | critical | accepted | Backdoored `coincurve` release would compromise every signature; major-range pin + `pip-audit` only | TM S11 |
| `SUPPLY-NOPIN` | medium | accepted | No pinned transitive dep hashes — deliberate for a *library* | TM gap #15 |
| `SUPPLY-GPGTAG` | low | open | PEP 740 attestations + SBOM now ship; a gpg-signed git tag is still optional | TM gap #17 |
| `FT-COVENANT-SPV-UNBUILT` | medium | deferred | The FT-in-covenant SPV cross-chain settle path is sig-gated only; SPV fusion unbuilt | FT-covenant note |
| `WAVE-DEFERRED` | low | deferred | WAVE protocol deferred; a pyrxd-minted WAVE name would be unresolvable until a consumer exists | wave note |

## 7. Legacy-ID disambiguation (read before cross-referencing)

The pre-existing numbering has collisions the auditor will otherwise trip on:

- **"#8" had three meanings** — the duplicate is now fixed in the threat model (same change as
  this brief). **Gap #8** = `SPV-SOLE-AUTHORITY` (network); the CLI `owner_pkh` gap that previously
  *also* numbered `#8` is now **gap #9** (`GLYPH-OWNERPKH`), and the rest of the "Known gaps" tail
  shifted `+1` to run `1–20` uniquely; **GitHub issue #8** = the signing-agent feature (hardening
  **H1**), unrelated to either gap.
- **"R1" is overloaded** but consistent in meaning: the REF-authenticity / fake-singleton residual
  (`SWAP-R1`) and the maker free-option residual (`SWAP-FREEOPT`) both trace to "R1" in different
  docs; the watch package separately uses local `LOW-R2`/`LOW-R3` tags (unrelated).
- **"F-01" ≠ "F-001"**: `F-0x` are 2026-05-29 Bitcoin-SPV audit findings; other docs use `F-0xx`
  (gravity) and `pitfall #1..#14` (the SPV how-to) as independent local schemes.
- **"SeenStore" names two things**: the swap-coordinator `SeenStore`/`DurableSeenStore`
  (`SWAP-SEEN1`) and the watch-layer dedup durability (`WATCH-SEENSTORE-DUR`).
- The 20th threat scenario is id'd **R1** (line ~300) rather than `S20`; this brief calls the
  swap-side residual `SWAP-FREEOPT` and the REF-authenticity one `SWAP-R1`.

## 8. The corpus — how to exercise the claims

- **Local CI:** `task ci` (lint, format, mypy on `pyrxd.security`, full pytest, 100% security-pkg
  + 85% overall coverage). Reproduces the GitHub gates one-for-one.
- **Swap consensus on a real node** (opt-in, skips without docker/image):
  `RADIANT_REGTEST=1 pytest tests/test_htlc_regtest_e2e.py -m integration` (Radiant HTLC: claim,
  wrong-preimage, premature/matured CSV refund, the `R1` fake-singleton acceptance);
  `XCHAIN_REGTEST=1 pytest tests/test_xchain_swap_regtest_e2e.py -m integration` (full BTC↔RXD);
  `XCHAIN_ETH_REGTEST=1 pytest tests/test_xchain_eth_swap_regtest_e2e.py -m integration` (ETH↔RXD).
- **Red-team suite:** `tests/test_gravity_red_team.py` (1500+ lines) documents known covenant
  concerns; `tests/test_xchain_eth_adversarial_e2e.py` covers hostile-maker/taker scenarios.
- **Per-primitive:** `tests/test_capped_fee_source.py`, `tests/test_seen_store.py`,
  `tests/test_agent_signer.py`, the SPV verifier + differential tests under `tests/`.

## 9. References

- [`docs/concepts/architecture.md`](docs/concepts/architecture.md) — the L0–L4 module map + trust boundaries.
- [`docs/how-to/spv-verification-pitfalls.md`](docs/how-to/spv-verification-pitfalls.md) — the SPV pitfall catalogue.
- [`docs/runbooks/incident-response.md`](docs/runbooks/incident-response.md) — the internal handling flow.
- Design notes under [`docs/solutions/design-decisions/`](docs/solutions/design-decisions/) — the
  capped-fee trust boundary, the SPV-swap deprecation, the coin-type default.
- `src/pyrxd/gravity/watch/README.md` — the watchtower's own v1/v2 posture + residuals.

---

*Freeze the audited commit SHA in the header at commission time; re-run this brief's residual
inventory if `main` has moved materially since.*

---

# Part IV — Security Review Playbook

A working notebook of the techniques that found **real bugs** in
pyrxd's 0.5.0 and 0.5.1 release cycles — not a generic methodology.
Each section names the technique, the actual finding it produced, and
the cases where it applies vs. where it doesn't.

Use this when starting a review on pyrxd itself, or as a reference
when bootstrapping a review of a sibling project in the Radiant
ecosystem.

## Scope and limits

This document captures **what worked on pyrxd** between roughly
2026-04-29 (0.2.0) and 2026-05-14 (0.5.1). It is biased toward:

* Wire-format builders that emit bytes the rest of the ecosystem
  parses.
* Parsers that consume attacker-supplied input (block-explorer
  pastes, ElectrumX responses, hostile reveal scriptSigs).
* Library code shipped to PyPI under MIT/Apache — the audience is
  downstream SDK consumers, not end users.

It is **not** a comprehensive Radiant-ecosystem methodology. If your
target is a frontend wallet, an indexer, or pure tooling without
on-chain serialization, only a subset of the techniques here will
apply. The "When it applies / when it doesn't" subsection of each
case study calls that out.

## Per-repo intake checklist

Before picking which techniques to run on a new repo, answer five
questions. The Yes answers map to the case studies below.

| Question | If yes → | If no → |
|---|---|---|
| Does the repo emit bytes that another implementation has to parse (transactions, contracts, CBOR, BIP-32 paths)? | §1 golden-vector pinning | Skip §1 |
| Is there a canonical reference implementation in another language? | §2 cross-implementation byte-diff | Skip §2; §1 carries the load alone |
| Does the repo expose any parser to attacker-controlled input? | §3 trust-boundary fuzz contract | Skip §3 |
| Is the repo about to ship a release with non-trivial new surface? | §4 multi-reviewer panel | Optional |
| Is the repo public? | §5 mechanical leak-checking | Skip §5 (private repos still benefit but the urgency is lower) |

If you got at most one Yes, this playbook isn't the right tool —
spawn the `security-sentinel` reviewer alone via the `/security-panel`
skill (see `.claude/skills/security-panel.md`) and call it.

If you got three or more, run them in the order listed: §1 builds the
golden vectors §2 will diff against; §3 hardens the parser side; §4
fans the multi-reviewer panel out across the cleaned tree; §5 is the
mechanical guard that runs in CI from then on.

---

## §1 — Golden-vector pinning against mainnet

**What it does.** For every wire-format builder, capture real
on-chain bytes for a known-good transaction and assert
`build(...) == GOLDEN`.

**What it found.** Two critical bugs that 49 round-trip tests missed:

1. **M1 V1 dMint mint scriptSig push convention.** Pre-0.5.0,
   `build_mint_scriptsig` pushed `<inputHash> <outputHash> <nonce>
   <0x00>` (72 bytes total). The canonical mainnet convention is
   `<0x04 nonce(4)> <0x20 inputHash(32)> <0x20 outputHash(32)>
   <0x00>` — same length, different push order. The old shape
   produced mint transactions the covenant rejects 100% of the time.
   M1 had never successfully spent a mainnet contract until this
   bug was found by walking real bytes against the builder's output.
   Verified fixed at txid `c9fdcd34…e530`.
2. **V2 mint reward output emitted plain P2PKH at vout[1].** The
   covenant requires the same 75-byte FT-wrapped reward as V1
   (`build_dmint_v1_ft_output_script`). Caught pre-V2-mainnet-deploy
   when the audit panel walked the V2 builder against the V1 golden.
   Would have been a 100% rejection on every V2 mint.

**Why round-trip tests miss this.** `assert parse(build(x)) == x`
proves the builder and parser are self-consistent. Both can harbor
**coordinated bugs** invisible to every round-trip assertion —
they were authored from the same flawed mental model. Real-world
example here: the M1 builder *and* the M1 parser agreed on the wrong
push order. Mainnet didn't.

**Where pyrxd carries this.** Six golden-vector test classes pin
every wire-format builder pyrxd ships:

| Builder | Test class | Mainnet ref |
|---|---|---|
| `build_ft_locking_script` (75 B) | `TestFtLockingScriptMainnetGolden` | RBG transfer `ac7f1f70…0ae4` |
| `build_nft_locking_script` (63 B) | `TestNftLockingScriptMainnetGolden` | Glyph NFT `27390efa…be7e` |
| `build_commit_locking_script` (75 B, FT + NFT) | `TestCommitLockingScriptMainnetGolden` | GLYPH deploy `a443d9df…878b` |
| `decode_payload` + `build_reveal_scriptsig_suffix` (65 569 B w/ embedded PNG) | `TestCborPayloadMainnetGolden` | GLYPH reveal `b965b32d…9dd6` |
| `build_dmint_v1_contract_script` (241 B) | `TestV1GoldenVectorGlyphPattern` | GLYPH deploy reveal vout 0 |
| `build_mint_scriptsig` (72 B) + 4-output mint shape | `TestCovenantShape` | snk `146a4d68…f3c` + PXD `c9fdcd34…e530` |

**Mechanics — how to add one in roughly 20 minutes.**

1. Find a mainnet transaction known to use the format you're building.
   For Glyph/dMint, the [Radiant Glyph Guide][rgg]'s §17 has a
   table; otherwise `gh api repos/<org>/<repo>/contents/...` against a
   working implementation's test fixtures, or `getrawtransaction`
   against your full node.
2. Fetch the raw tx hex; extract the specific output (or scriptsig)
   bytes you want to pin. For payloads >a few kB, check them in as a
   binary fixture under `tests/fixtures/` (see `glyph_reveal_cbor.bin`
   for the canonical example).
3. Write one test class that asserts:
   - `build(...) == captured_bytes` (the core assertion)
   - The captured bytes pass your own classifier (round-trips with
     the parser side, but the *baseline* truth is the on-chain bytes,
     not the round-trip)
   - `extract_*(captured_bytes)` recovers the inputs (proves bytes
     and parser agree)

The test file in `tests/test_glyph_dmint.py::TestCommitLockingScriptMainnetGolden`
is a good template — 79 lines, three assertions, no dependencies
beyond the builder itself.

**When it applies.** Any function whose output is a byte string
another implementation must parse. Bonus when the on-chain consumers
are covenant-driven (Radiant covenants reject byte-shape mismatches
100% of the time — silent corruption is impossible, but so is
"works on testnet").

**When it doesn't.** Pure business logic, frontend rendering,
tooling without serialization, RPC client wrappers that round-trip
JSON unmodified. Don't manufacture golden vectors where there is no
canonical wire format to pin against.

**Anti-pattern to avoid.** Don't write goldens against your own
testnet broadcasts. The point is *independent ground truth* — bytes
emitted by a different implementation (Photonic, glyph-miner,
Photonic Wallet, etc.) on mainnet. A self-loop test pinning your own
output against your own output is just a slower round-trip test.

[rgg]: https://github.com/Radiant-Core/radiant-glyph-guide

---

## §2 — Cross-implementation byte-diff

**What it does.** Diff your builder's output against the canonical
reference implementation, at the byte level, with the explicit rule:
"Photonic (or whatever the reference is) is the default; deviate
explicitly and document the reason when the reference is wrong."

**What it found.** The audit pattern that catches the bugs §1's
golden vectors only catch retrospectively (after they ship to
mainnet). Used during 0.4.0 → 0.5.0 to validate the V1 deploy and
V1 mint flows before the first mainnet broadcast.

The rule cuts both ways:
- The Photonic V1 mint scriptSig push order is what pyrxd had to
  match — pyrxd had it wrong, Photonic had it right.
- Photonic's `parseDmintScript` ships as V2-only in master — but
  the live ecosystem runs V1. pyrxd correctly deviated and
  documented `docs/DMINT_RESEARCH.md` §7 explaining
  why.

**Where pyrxd records the diff convention.** Two places, both
public-tracked:

- `docs/DMINT_RESEARCH.md` — per-decision table:
  Photonic file/line, what value Photonic emits, what pyrxd emits,
  and the reason for any divergence.
- `docs/DMINT_RESEARCH.md` — the same for the broader
  Photonic source-tree walk.

**Mechanics.** Read the reference implementation *with the goal of
emitting matching bytes* — not "understand the protocol." Capture
each builder call and decode call as a row in a divergence table:

| Photonic file:line | Photonic emits | pyrxd emits | Match? | Reason if not |
|---|---|---|---|---|
| `script.ts:152-213` (ftCommitScript) | `aa20<hash>88…` | `aa20<hash>88…` | ✓ | — |
| `script.ts:704-766` (dMintScript) | V2 9-state-item layout | V1 3-state-item layout | ✗ | Photonic master ships V2-only emit; live chain runs V1 |

The act of filling the table *is* the audit. Each "match" row is a
no-op confirmation; each "no match" row is either a real divergence
(documented) or a bug (fix and re-row).

**When it applies.** Protocols with a canonical reference
implementation in another language. For Radiant: Photonic Wallet
(Glyph/dMint/WAVE), glyph-miner (dMint mining), RXinDexer (indexer
classifiers). For other ecosystems: BIP-32 reference vectors, the
Bitcoin Core RPC reference, etc.

**When it doesn't.** Protocols with no second implementation, or
where the second implementation is *itself* a fork of yours. Then §1
golden vectors against on-chain bytes are the strongest baseline you
can write.

**The deferral rule.** Don't write a divergence row that says
"Photonic does X, we'll do Y because X is suboptimal" without
mainnet evidence. Either:

1. Find an on-chain transaction emitted by a *third* implementation
   that agrees with X — Photonic is right, you match.
2. Find an on-chain transaction emitted by a third implementation
   that agrees with Y — Photonic is wrong (or outdated), document
   and deviate.
3. Neither exists — the protocol surface isn't validated; **don't
   ship it**, mark experimental, defer to a future release where one
   side has been validated.

The V2 dMint reward bug was caught by exactly this rule: pyrxd's
V2 path matched Photonic's V2 emit, but no V2 contract has been
deployed to mainnet → no third-party validation possible → the V2
path is now quarantined behind `V2UnvalidatedWarning` (see §6 below
for how this connects to release hygiene).

---

## §3 — Trust-boundary fuzz contract

**What it does.** For every parser that consumes attacker-supplied
input, assert one specific contract:

> Return a structured value, or raise one specific exception type.
> Any other exception type is a bug — the parser leaking its
> internal failure mode past its trust boundary.

**What it found.** A `cbor2.CBORDecodeError` escaping `decode_payload`
that slipped past the inspect-tool's `except ValidationError`
handler. The inspect tool's browser flow crashed instead of cleanly
classifying the input as malformed. Fix was a one-line wrap inside
`decode_payload`; without the fuzz test, the bug would have only
been visible to a user who happened to paste exactly the wrong
bytes.

**Where pyrxd carries this.** `tests/test_fuzz_parsers.py` ships
eight Hypothesis targets, all asserting the same contract via the
shared `_fail_unexpected()` helper:

```python
def _fail_unexpected(target: str, exc: BaseException, raw: bytes | str) -> None:
    payload = raw.hex() if isinstance(raw, (bytes, bytearray)) else repr(raw)
    pytest.fail(
        f"{target} raised unexpected {type(exc).__name__}: {exc}\n"
        f"  input ({len(raw)}): {payload}"
    )
```

The eight targets:

1. `decode_payload` — CBOR decode boundary
2. `DmintState.from_script` — variable-length opcode walker
3. `GlyphInspector.extract_reveal_metadata` — push-data walker
4. `GlyphInspector.find_glyphs` — script classifier dispatch
5. `_inspect_script` — CLI/browser inspect dispatch
6. `_classify_input` — top-level inspect classifier
7. `GlyphRef.from_bytes` / `from_contract_hex` — fixed-shape ref
   decoders
8. Round-trip: `build_mutable_scriptsig` → push-data walker recovers
   the embedded CBOR (proves builder and parser agree on the
   structural contract, separate from the byte-shape contract §1
   covers)

Plus five atheris coverage-guided harnesses under
`scripts/fuzz_atheris/`, hitting the same surface with libFuzzer
mutation feedback.

**Mechanics — adding a fuzz target.**

1. Identify the parser function that consumes attacker input. "Where
   does untrusted bytes/text first cross into your code?" — that's
   the boundary.
2. Write one `@given(data=st.binary(...))` decorator + a try/except
   asserting the contract:

```python
@given(data=st.binary(min_size=0, max_size=1024))
@settings(max_examples=_budget(400), suppress_health_check=[HealthCheck.too_slow])
def test_my_parser_only_validation_error(data):
    try:
        my_parser(data)
    except ValidationError:
        # expected: parser converted a malformed input cleanly
        pass
    except Exception as exc:
        _fail_unexpected("my_parser", exc, data)
```

3. Run at CI budget (~1.5 s for 400 examples). If it finds a
   counterexample, the failure message prints the offending bytes
   hex-encoded — paste it into a reproduction unit test before
   fixing the parser.

**When it applies.** Any parser at a trust boundary: HTTP request
handlers, RPC dispatchers, file-format readers, script walkers,
CBOR/JSON/protobuf decoders. Anywhere the input is "whatever the
attacker decided to send."

**When it doesn't.** Internal-only parsers consuming data your own
code wrote three lines earlier. The trust boundary is *external
input* — fuzzing your own serialization round-trip is a §1
golden-vector concern, not a §3 fuzz concern.

**Cost.** The Hypothesis suite runs in ~1.5 s at CI budget (400
examples per target). The atheris harnesses are overnight-run
material — invoke via `scripts/fuzz_overnight.sh` against an 8-core
box. Don't put atheris on the per-commit CI path.

**Anti-pattern.** A `try/except: pass` with no comment looks like a
broad swallow even when it's correct. Either add a comment naming
the expected contract (`# expected: parser converted a malformed
input cleanly`) or pin the exception type tightly. CodeQL's
`py/empty-except` rule will flag the comment-less form.

---

## §4 — Multi-reviewer panel

**What it does.** Spawn a fan-out of specialised reviewer subagents
in parallel against the same target (a PR, a branch's diff, or a
specific path). Each reviewer focuses on its own dimension —
security, architecture, simplicity, performance, etc. — and returns
a short report. You synthesize.

**What it found.** Almost everything in the 0.5.0 audit pass: the
V2 reward-shape bug (red-team chain-conformance reviewer),
unnecessary V2 surface that turned into the `V2UnvalidatedWarning`
quarantine (architecture-strategist), the broad-except leak that
turned into §3 (security-sentinel + pattern-recognition-specialist),
the missing FT golden vector (pattern-recognition-specialist).
0.5.0's CHANGELOG attributes findings to specific reviewers.

**The roster.** Eight slots, three are language-specific. For a
Python repo:

| Slot | Reviewer | What it catches |
|---|---|---|
| Security | `compound-engineering:review:security-sentinel` | Auth, input validation, secrets, OWASP top-10 patterns |
| Pattern recognition | `compound-engineering:review:pattern-recognition-specialist` | Anti-patterns, naming inconsistencies, duplication |
| Architecture | `compound-engineering:review:architecture-strategist` | Layering, coupling, abstraction boundaries |
| Simplicity | `compound-engineering:review:code-simplicity-reviewer` | YAGNI violations, premature abstraction |
| Performance | `compound-engineering:review:performance-oracle` | Algorithmic complexity, hot-path issues |
| Data integrity | `compound-engineering:review:data-integrity-guardian` | Migrations, transactions, persistent state |
| Language quality | `compound-engineering:review:kieran-python-reviewer` (or `kieran-typescript-reviewer`, `kieran-rails-reviewer`) | Idiomatic patterns, type safety, maintainability |
| Red team | `general-purpose` with a red-team prompt | Adversarial mindset; "what's the worst thing a hostile caller could do here?" |

There is **no dedicated red-team reviewer**; the eighth slot is a
`general-purpose` agent given a red-team-styled prompt. Lean
heavily on "what assumptions does this code make about its caller
that an attacker could violate?"

**Where pyrxd carries this.** As a Claude skill at
`.claude/skills/security-panel.md` (this PR adds it). Invoke with
`/security-panel`; it prompts for scope (current branch diff, a
specific path, or a PR number) then fans the eight reviewers out in
parallel.

**Mechanics.** The skill instructs the orchestrating Claude
instance to make **eight `Agent` tool calls in a single message** so
they run concurrently. Each agent gets a prompt scoped to its
dimension plus the same target description. The skill defines an
output schema — each reviewer returns under 400 words; the
orchestrator synthesizes findings into a single report with severity
buckets (critical / high / medium / low / info) and a "consensus
vs. one-reviewer-only" tag on each finding.

**When it applies.** Pre-release audits. Risky refactors. New
features touching wire formats or trust boundaries. Any change where
the cost of a bug is high and the diff is large enough that single-
reviewer fatigue is a real risk.

**When it doesn't.** Per-commit reviews on a routine PR — you'll
burn tokens for low marginal value. Documentation-only PRs (run
`every-style-editor` alone). Mechanical chores (linting, dep bumps,
CI config tweaks).

**Cost.** Each reviewer agent is a full Claude run with its own
context. Eight in parallel on a 2 000-line diff is roughly the
token cost of a heavy investigation. Budget accordingly.

**Anti-pattern: reviewer overload.** Running the full panel on
every PR trains the team to ignore reviewer findings ("noise"). Save
it for the moments where the signal-to-noise actually warrants it.

---

## §5 — Mechanical leak-checking

**What it does.** A `task ci` check that scans every tracked
markdown/RST file for two leak classes:

1. **Markdown link targets pointing into `.gitignore`d paths**
   (`[text](docs/design/foo.md)` when `docs/design/` is private).
   Such links break in every clone and leak the existence of
   private files via the link text.
2. **Absolute home-directory paths with a baked-in username**
   (`/home/<user>/...` or `/Users/<user>/...`) anywhere in doc
   body, link or prose or fenced code block. These leak the
   author's username and local layout. When they point into a
   sibling private project, they leak that project's existence
   too.

**What it found.** A single grep at the end of the 0.5.1 release
sprint surfaced **18 leaks across 6 tracked docs** that had been
public on `origin/main` for over a week:

- One `file://` markdown link directly into the author's private
  `~/.claude/` auto-memory directory.
- Two prose mentions of that private memory file's name.
- About fifteen `/home/<user>/apps/…` paths, several pointing into
  a private sibling-project group (leaking the existence of those
  private projects via the path name alone).
- A VPS IP and a full `ssh ericadmin@<ip> -- sudo docker exec ...`
  line — username + IP + the fact the VPS runs docker as sudo.

Every leak was old. None had been caught by review. None had been
caught by CI. The mechanical scan ran in 60 ms.

**Where pyrxd carries this.** `scripts/check-no-private-links.py`.
Two checks, both run on every invocation:

1. Link-target check — link is gitignored.
2. Home-path regex check — `/home/<user>/...` or
   `/Users/<user>/...` in any tracked doc.

Wired into `task ci` so the pre-push hook catches new leaks before
they reach `origin`. The hardened version was deliberately narrow:
it does **not** flag `~/...` (username-agnostic — the correct way
to document `~/.pyrxd/config.toml`), `/root/...` (no username),
or `/tmp/...` (scratch paths carry no user identity).

**Mechanics — porting to another repo.** The script is portable
as-is. Drop `scripts/check-no-private-links.py` into the target
repo, add it to `task ci` (or whatever the equivalent test
runner is), and add a `.gitignore` block for repo-specific private
paths (most repos want at least `.claude/`, `.worktrees/`,
`logs/`). Done.

**When it applies.** Every public repo. Even when the techniques in
§1–§4 don't fit (frontend-only, doc-only), this one always does.

**When it doesn't.** Truly-private internal repos where there's no
publication surface at all. Even then, the discipline pays off if
you ever consider opening the repo later.

**Anti-pattern.** Methodology theatre — adding a "Security
Checklist" markdown file that nobody reads is worse than nothing,
because it creates the appearance of coverage. The mechanical
check, in CI, is the only form that catches the next leak.

---

## What this playbook is NOT

Worth being explicit, because it's tempting to over-read the success
of one release cycle as a general methodology:

* **Not a substitute for a deep-review pass on a new repo.** The
  techniques here found bugs on a *familiar* codebase. The first
  pass on an unfamiliar repo should still be the multi-reviewer
  panel from §4, not the playbook in isolation.
* **Not a guarantee.** Six golden vectors caught two on-chain-
  rejection bugs. They would not have caught a covert ECDSA-nonce
  reuse, a timing side-channel, or a logic error in the wallet's
  coin-selection. Different attack classes need different lenses.
* **Not stable.** This document will go stale. Re-derive the
  techniques from the next release cycle's *actual* findings; don't
  preserve sections out of habit.

## Update protocol

Add a new case study when:

* A specific technique finds a real bug that the other techniques in
  this playbook would have missed.
* You ship a security fix and want the lesson to compound.

Remove or rewrite a case study when:

* It no longer reflects the actual workflow.
* The technique it documents is now mechanical (lives in `task ci`
  rather than in human review).
* A subsequent finding contradicts it.

The point is the case studies, not the index. Length is fine as long
as every section names a real finding.

---

# Part V — Red-Team Checklist

**Purpose:** a focused half-to-full-day adversarial review of the pyrxd v0.3 wallet/CLI surface. The threat model (Part II above) describes what we *intend* to protect; this checklist exercises whether the implementation actually does.

**How to use it:**

1. Block out 4-8 hours. Treat it like a separate task, not part of feature work.
2. Open three terminals: one running `pyrxd` commands, one with `git` + `gh issue create`, one with a model (Sonnet recommended) for "what edge case am I missing on this section?"
3. Work through the sections in order. Each one has explicit commands, expected outcomes, and a "what to file" pattern.
4. **File a GitHub issue for everything weird, even if you're not sure it's a bug.** Better to overproduce issues and close them than to lose findings.
5. Mark items DONE as you go. Don't skip — the boring sections often surface things.

**What this checklist is NOT:**

- A pen-test. We're not trying to find zero-days; we're trying to surface footguns and broken-promises.
- A substitute for fuzz testing (issue #10) or a third-party audit.
- A one-time activity. Re-run before each minor release with the diff in mind.

---

## 0. Pre-flight (10 min)

- [ ] Pull latest main: `git pull origin main`
- [ ] Confirm full test suite green locally: `PYTHONPATH=src python -m pytest tests/ -q`
- [ ] Confirm ruff + bandit clean: `ruff check src tests examples && bandit -r src/ -c pyproject.toml --quiet`
- [ ] Build a fresh venv specifically for this session so module state can't bleed between commands
- [ ] Set `PYRXD_WALLET_PATH=/tmp/redteam-$(date +%s)/wallet.dat` so all wallet ops happen in a throwaway dir
- [ ] Have `gh issue create` ready (or open https://github.com/Radiant-Core/pyrxd/issues/new in a browser)

---

## 1. Mnemonic exposure surface (60-90 min)

This is the highest-stakes section. The mnemonic is the master key; any path that exposes it is a finding.

### 1.1 Stdout / stderr leakage

- [ ] Run `pyrxd wallet new --json --yes` and check that the mnemonic appears in stdout (expected) and NOT in stderr.
- [ ] Run `pyrxd wallet new --json --yes 2>/dev/null` and confirm the mnemonic still emits to stdout.
- [ ] Run `pyrxd wallet new --json --yes >/dev/null` and confirm stderr is silent (no mnemonic on the unredirected stream).
- [ ] Run `pyrxd wallet new` (interactive) and confirm the mnemonic appears once, in the box, and waits for Enter.
- [ ] After the Enter, scroll up in the terminal — confirm the mnemonic is still visible (this is expected; we don't clear scrollback). File issue if the user has no warning about this.
- [ ] Run `pyrxd wallet new` then immediately `pyrxd wallet new` (second one should fail with "already exists"). Confirm the second invocation does NOT generate a new mnemonic and abort, only to leak it via stderr or anywhere else. The fast-fail before mnemonic generation is the safety property.

### 1.2 Failure-mode leakage

- [ ] Run `pyrxd wallet load` and enter a known-wrong mnemonic. Confirm the error message says "Could not decrypt" without echoing your input.
- [ ] Same with `--debug`. Confirm the traceback shows function names and source lines but never your input value.
- [ ] Try a mnemonic with only 11 words. Confirm rejection. Check that error doesn't echo the partial input.
- [ ] Try a mnemonic where one word is misspelled (e.g., `aboutt` instead of `about`). Confirm rejection. Check that error doesn't echo the misspelling.
- [ ] Try a mnemonic with leading/trailing whitespace. Should normalize and succeed (if the rest is valid).

### 1.3 Storage leakage

- [ ] Inspect `wallet.dat` after creation: `file /tmp/.../wallet.dat`. Confirm not human-readable (encrypted blob).
- [ ] Inspect with `xxd | head -5` or similar. Confirm no plaintext mnemonic words appear.
- [ ] `stat -c '%a' /tmp/.../wallet.dat` should show 600.
- [ ] `stat -c '%a' /tmp/.../` (the parent dir) — note the mode. If the test creates a wider parent, that's a finding for `pyrxd setup` defaults.
- [ ] After running `pyrxd address`, check `~/.bash_history` (or your shell equivalent). The command should be there but no mnemonic.
- [ ] Search for any tempfiles under `/tmp` containing mnemonic words after a `wallet new`: `grep -rl "abandon abandon" /tmp 2>/dev/null` (with whatever first two words you got). Should be nothing.

### 1.4 Network leakage

- [ ] Run `pyrxd balance --refresh` against a wallet, capture the websocket traffic with `tcpdump` or by pointing `--electrumx` at a logging mock. Confirm the mnemonic NEVER appears in any outbound bytes. (Only address derivations / script hashes should go over the wire.)
- [ ] Same for `pyrxd glyph list`.

### 1.5 Memory leakage (best-effort, hard to verify)

- [ ] Add a `print(repr(wallet))` somewhere temporarily and confirm the mnemonic / seed don't appear in the dataclass repr.
- [ ] Use `gc.get_objects()` after a `wallet new` and grep for known mnemonic words. (Will probably find them — `SecretBytes.zeroize()` is best-effort.) File a "doc / known-limit" issue rather than a fix issue.

**File issues for:** any path where the mnemonic shows up somewhere it shouldn't, including pytest output captures, logs, or response bodies.

---

## 2. Wallet file integrity & permissions (30-45 min)

### 2.1 File mode enforcement

- [ ] Create a wallet, then `chmod 0644 /tmp/.../wallet.dat`, then try `pyrxd wallet load`. Confirm explicit refusal with a chmod-fix message.
- [ ] Same with 0o755 and 0o777.
- [ ] Set 0o400 (read-only owner). Should still work — the check is for group/other read bits, not write bits.

### 2.2 Tampering

- [ ] Edit one byte in the middle of the encrypted ciphertext (`dd if=/dev/zero of=wallet.dat bs=1 count=1 seek=200 conv=notrunc`). Try to load. Should fail with "Could not decrypt" — AES-GCM tag check should catch this.
- [ ] Truncate the file to half its size. Try to load. Should fail with a clean error.
- [ ] Create an empty file, mode 0o600. Try to load. Should fail with "too short" or similar.
- [ ] Create a file with the v2 version byte but garbage afterwards. Should fail with decrypt error.

### 2.3 Atomic-write guarantees

- [ ] In one terminal, run `pyrxd wallet new` interactively to the Enter gate. Don't press Enter.
- [ ] In another terminal, check what's in `~/.pyrxd/`. Should be nothing yet (mnemonic-display happens before save).
- [ ] Press Enter to complete. Save happens. Now repeat the wallet new flow but Ctrl-C after the gate but before the save completes (small window). Check that no half-written wallet.dat exists.

### 2.4 Cross-platform

- [ ] (If you have access) Run on macOS — confirm mode-check still fires.
- [ ] (If you have access) Run on Windows / WSL — confirm the mode check is skipped (we documented this) and the wallet works.

**File issues for:** any path where wallet load succeeds with a file it shouldn't, or fails with a file it should accept.

---

## 3. CLI input fuzzing (manual fuzz, 30-45 min)

This is a sampler; full coverage is issue #10.

### 3.1 Mnemonic input

- [ ] Mnemonic with NUL bytes: `printf "abandon\x00abandon..." | pyrxd wallet load`
- [ ] Mnemonic >10MB (paste a wall of text). Should be rejected without crashing.
- [ ] Mnemonic with mixed-case (`Abandon Abandon ...`). Should normalize to lowercase via the BIP39 wordlist or fail cleanly.
- [ ] Mnemonic with non-ASCII bytes. Should be rejected without crashing.

### 3.2 Address arguments

- [ ] `pyrxd glyph deploy-ft meta.json --supply 1000 --treasury "$(python -c 'print("A"*1000)')"`. Should reject without crashing.
- [ ] Address with leading/trailing whitespace. Probably accepted — test what it does.
- [ ] Address with embedded null. Reject cleanly.

### 3.3 Numeric arguments

- [ ] `--supply -1`. Should reject.
- [ ] `--supply 0`. Should reject.
- [ ] `--supply 99999999999999999999999999999`. Click should reject as "not an int" or pyrxd should reject as out-of-range.
- [ ] `--fee-rate 0`, `--fee-rate -1`. Should reject (we already test this in unit tests).

### 3.4 Path arguments

- [ ] `--wallet "/etc/passwd"`. The load path will fail (mode check / not a wallet file). Confirm the error doesn't expose contents.
- [ ] `--wallet "../../../etc/passwd"`. Path traversal — should be rejected by file-existence check or by mode check.
- [ ] `--config /dev/zero`. Should fail cleanly, not hang reading infinite bytes.

### 3.5 Argument combinations

- [ ] `pyrxd --json --quiet wallet new`. Already rejected (mutually exclusive); confirm.
- [ ] `pyrxd --json wallet new` (no `--yes`). Already rejected; confirm.
- [ ] `pyrxd --json --yes wallet new --mnemonic-words 13`. Click rejects "13" as not in the choice list; confirm.
- [ ] All flags after the subcommand: `pyrxd wallet new --json --yes`. Click handles this; confirm output is clean.

**File issues for:** any input that crashes (uncaught traceback at exit code 4, not 1/2/3) or that produces an exit code that doesn't match the docs.

---

## 4. Network failure modes (45-60 min)

### 4.1 ElectrumX unreachable

- [ ] `pyrxd --electrumx wss://does-not-exist.example/ balance --refresh`. Should fail with NetworkError, exit code 2, fix-suggestion mentions the URL.
- [ ] `pyrxd --electrumx ws://localhost:50001/ balance` (insecure scheme without flag). Should reject before trying to connect.
- [ ] `pyrxd --electrumx http://example.com/ balance`. Wrong scheme. Should reject.
- [ ] Drop your network connection mid-`balance --refresh`. Confirm timeout, clean error.

### 4.2 ElectrumX returns garbage

This needs a mock; consider running `examples/`-style tests or building a `nc` listener. For a quick smoke test:

- [ ] In one terminal: `nc -l 50022` (or use openssl s_server for TLS). Send arbitrary bytes when `pyrxd` connects.
- [ ] In another: `pyrxd --electrumx ws://localhost:50022/ --network mainnet balance` (with `--allow-insecure`-equivalent if pyrxd had one — current code rejects `ws://` without a flag).
- [ ] Confirm pyrxd doesn't crash, hangs, or expose internals when given non-JSON-RPC bytes.

### 4.3 Slow / unresponsive ElectrumX

- [ ] Point pyrxd at a slow loopback that holds the connection open without responding. Confirm there's a timeout, not an indefinite hang.

### 4.4 Bitcoin data source (Gravity tangential)

- [ ] If you have credentials, point a Gravity flow at a deliberately-wrong `mempool.space` URL. Confirm clean error.

**File issues for:** crashes (exit code 4), indefinite hangs, or any error path that leaks an internal trace without `--debug`.

---

## 5. Glyph metadata trust (30 min)

Threat scenario S7 from the threat model. As-shipped, the broadcast summary now includes a `_metadata_summary` section, so verify it does what we want.

### 5.1 Metadata visibility in confirmation

- [ ] `pyrxd glyph init-metadata --type ft --out /tmp/ft.json`
- [ ] Edit the file: change `name` to "ATTACKER NFT", set `description` to something obvious.
- [ ] Run `pyrxd glyph deploy-ft /tmp/ft.json --supply 100 --treasury <some addr>` (use a fake-but-valid-shape addr if not testing on chain).
- [ ] At the confirmation prompt, confirm the "Metadata" section shows the modified name and description. Abort the broadcast.
- [ ] Repeat with a metadata file that has a `creator` block (manually added). Confirm `creator: pubkey=...` appears in the summary.
- [ ] Repeat with a `royalty` block. Confirm royalty bps and address appear, and any splits appear with their own bps.

### 5.2 Metadata that triggers validation errors

- [ ] Edit a metadata file to have `protocol: ["NFT", "FT"]`. Should reject (mutually exclusive).
- [ ] Edit `decimals: -1` or `decimals: 19`. Should reject (out of range).
- [ ] Edit `image_sha256: "not-hex"`. Should reject (not 64 lowercase hex).
- [ ] Edit `protocol: ["AUTHORITY"]` (no NFT). Should reject (AUTHORITY requires NFT).

### 5.3 Metadata size

- [ ] Create a metadata.json with a multi-megabyte `description`. Should be rejected at parse or at CBOR-encode time.
- [ ] Create a metadata.json with 100 attrs. Already capped at 64; confirm rejection.

**File issues for:** any metadata edit that gets through without showing in the summary, or any reject path that doesn't surface the metadata's offending field.

---

## 6. Confirmation prompts and abort behavior (15 min)

- [ ] `pyrxd glyph mint-nft meta.json` → at the confirmation prompt, type "n". Confirm clean abort with exit code 1, no broadcast.
- [ ] Same but Ctrl-C the prompt. Should be a clean abort.
- [ ] Same but pipe `echo "n" |` to skip interactivity. Confirm abort, no surprises.
- [ ] `pyrxd glyph mint-nft --json --yes meta.json` (no wallet present so it'll fail before broadcast anyway, but verify the `--yes` is accepted).

**File issues for:** any prompt that ignores the "n" answer, or that causes a partial-broadcast on Ctrl-C.

---

## 7. Setup command sanity (15 min)

- [ ] `pyrxd setup --no-interactive` on a fresh user account. Should write config without prompting.
- [ ] `pyrxd setup` on a system with no Radiant Core node. Status should show "node: NOT reachable" and provide ElectrumX as a next step.
- [ ] `pyrxd setup` on a system with Radiant Core running. Status should show "node: reachable."
- [ ] `pyrxd --quiet setup --no-interactive` should print "todo" or "ok" only.

**File issues for:** misleading status messages or next-steps that don't match the actual state.

---

## 8. Concurrent / race conditions (30 min)

- [ ] Run two `pyrxd wallet new` in parallel against the same `--wallet` path. Whoever wins should win cleanly; the loser should fail with "already exists" not corrupt state.
- [ ] Run `pyrxd balance --refresh` while another process is editing the same wallet's address dict (via `pyrxd address`, which adds an unused-receive entry). Confirm one of: success, clean error, no corruption.
- [ ] `pyrxd setup --no-interactive` twice in parallel. Should be idempotent.

**File issues for:** any data corruption observed, or any error message that misrepresents what happened.

---

## 9. Documentation / README claims-vs-reality (15 min)

For each claim in README.md, confirm the actual command behaves as advertised:

- [ ] "Mnemonic shown ONCE — write it down" → confirm not shown again on subsequent runs.
- [ ] "ElectrumX async client with reconnect" → kill an established websocket, confirm pyrxd reconnects (or fails cleanly with a documented error).
- [ ] "RXD send / send-max" → both work via `RxdWallet` and `HdWallet`.
- [ ] "Glyph FT premine deploy via prepare_ft_deploy_reveal" → matches what the CLI's `glyph deploy-ft` does.
- [ ] "Encrypted persistence (HdWallet)" → file is encrypted, mode-checked, GCM-tagged.

**File issues for:** any documented capability that doesn't match the code.

---

## 10. SPV / Gravity data-source trust (45-60 min)

The SPV primitive is the highest-risk client-side layer — a forged proof releases RXD. The *why* behind each check lives in [`docs/how-to/spv-verification-pitfalls.md`](docs/how-to/spv-verification-pitfalls.md); this section is the hands-on attack list. (Covenant *correctness* is still audit territory — see below.) Drive these directly against `pyrxd.spv` / `pyrxd.gravity.covenant` / `pyrxd.network.bitcoin`.

### 10.1 Difficulty / header forgery (pitfalls §1, §12)

- [ ] Build a `CovenantParams(expected_nbits=…)`, then feed `SpvProofBuilder.build()` a header whose nBits (bytes 72:76) differs from the committed value. Confirm "does not match the committed" — and that it fires *before* the PoW check.
- [ ] Confirm `build_gravity_offer(..., reject_low_difficulty=True)` rejects a difficulty-1-class `expected_nbits` (`ffff001d`), and rejects a low-mantissa exp-0x1c target once `min_difficulty_nbits` is supplied.
- [ ] Confirm `require_spv_sole_authority_cleared("mainnet", audit_cleared=False)` raises, and `SpvProofBuilder.for_sole_authority(..., network="mainnet")` raises without the opt-in.

### 10.2 Merkle / coinbase (pitfalls §3, §6, §7)

- [ ] Feed `build()` a `pos` beyond the branch depth (`pos=2` at depth 1) → confirm "beyond branch depth" (the coinbase pos-aliasing bypass).
- [ ] Feed a null-outpoint (coinbase-shaped) tx → confirm the structural reject regardless of pos.
- [ ] Supply a `tx_block_height` that maps outside the fetched headers → confirm rejection (proof not bound to the resolved block).

### 10.3 Data source / confirmations (pitfalls §2, §9)

- [ ] Use `MultiSourceBtcFundingReader` for an above-dust value with only one source responding → confirm it fails closed (quorum required), not a silent single-source read.
- [ ] Mock a source reporting `block_height > tip` → confirm `get_raw_tx` raises "inconsistent confirmation data" (the `[1,tip]` floor).
- [ ] Mock one source OVER-reporting confirmations → confirm the conservative-minimum overrides it.

### 10.4 Parser parity (pitfalls §10, §11)

- [ ] Feed a non-canonical CompactSize varint (`0xfd 0x01 0x00`) → confirm rejection.
- [ ] Feed an output value with bit 63 set → confirm rejection.

**File issues for:** any of these that does NOT fail closed. Difficulty/forgery findings are CRITICAL-class — escalate immediately.

---

## After the session

- [ ] Total issues filed: count them. Aim for at least 5; if you have zero, you didn't look hard enough.
- [ ] Triage: tag each as `bug`, `enhancement`, `documentation`, or `wontfix`.
- [ ] Update this checklist with any sections that turned out to be useless or any new sections you wished existed.
- [ ] Add a note in `CHANGELOG.md` (in the "Unreleased" section, if it exists, or just at the top): "Red-team review N issues filed YYYY-MM-DD."
- [ ] Re-run after fixes have landed; confirm the issues are actually closed by the fixes.

## Things this checklist deliberately doesn't cover

- **Cryptographic primitive review** — that's the audit territory. We trust `coincurve` and `Cryptodome`.
- **Gravity covenant correctness** — that's the highest-value audit target and needs more than a half-day red-team.
- **Side channels** — out of scope per the threat model.
- **Performance / DoS** — important but a different kind of session.

If a section here exposed something bigger than this checklist can address, file it as an issue and link to the relevant section of Part II above.





