# dMint Research — Consolidated

> **Status note (updated 2026-06-30):** pyrxd now ships **full V2 deploy** support,
> **V1 mint** support against live mainnet contracts (M1), and **V1 deploy**
> support with byte-equal golden vectors against the live Radiant Glyph Protocol
> deploy (M2). The V2 contract builder, ASERT/LWMA/EPOCH/SCHEDULE difficulty
> bytecode, V1+V2 parsers, V1+V2 mint tx builders, an external-miner shim, a
> reference Python miner, AND a V1 deploy builder all ship today.
>
> **Authoritative sources for current dMint capability:**
> - [`docs/concepts/dmint-v1-deploy.md`](concepts/dmint-v1-deploy.md) — V1 deploy story end-to-end
> - [`src/pyrxd/glyph/dmint/`](../src/pyrxd/glyph/dmint/) — builders, parsers, miner, verifier, chain helpers
> - [`src/pyrxd/glyph/builder.py`](../src/pyrxd/glyph/builder.py) — `prepare_dmint_deploy`
> - [`examples/dmint_v1_deploy_demo.py`](../examples/dmint_v1_deploy_demo.py) — manual real-mainnet V1 deploy runner
> - [`examples/dmint_claim_demo.py`](../examples/dmint_claim_demo.py) — manual real-mainnet V1 mint runner
>
> **What's still genuinely future work:**
> - Auth NFT in the V1 deploy reveal (M2 demo omits this; GLYPH has it)
> - Premine FT output on V1 deploy (deferred per Photonic divergence #2)
> - Walking forward through mined-from contracts in `find_dmint_contract_utxos`
> - Live-mainnet V2 deploy proof (M3, deferred indefinitely — no ecosystem demand)
> - EPOCH DAA int64-overflow — **fixed upstream and re-enabled (DONE)**. All five
>   DAA modes ported and byte-matched to canonical Photonic.
> - Native fast miner — pyrxd ships a slow Python reference; users wanting
>   GPU/multi-core go through the external-miner shim to `glyph-miner`

---

# Part I — V2 dMint: Reverse-engineered from Photonic Wallet

**Date:** 2026-04-22
**Source:** `RadiantBlockchain-Community/photonic-wallet` (master, shallow clone to `/tmp/photonic-wallet`)
**Purpose:** concrete reference for implementing `GlyphProtocol.DMINT = 4` in pyrxd.

---

## 0. TL;DR — one sentence

Photonic Wallet's "dMint" is **PoW distributed minting**, not "one mint-contract spent-and-recreated per call by an authorized minter." It deploys one or more **PoW-gated mint contract UTXOs** that anyone can spend by solving a hash puzzle; each spend decrements an on-chain `height` counter, produces an FT reward output locked by the token's `tokenRef`, and re-creates the contract UTXO with the next height. No authorized-minter concept; no per-block rate cap — the rate limiter is **PoW difficulty**. This design matches REP-3010 (Glyph v2 dMint).

This differs from the mental model in the research prompt ("max_supply / per_block_cap / authorized_minter"). The closest mapping:
- max_supply ≈ `MAX_HEIGHT × REWARD × numContracts` (plus `premine`)
- per-block cap ≈ `numContracts` concurrent solvers (can all be spent in same block if difficulty allows)
- authorized_minter = **none** — anyone who solves PoW mints

If pyrxd needs an "authorized minter / rate-limited fungible issuance" primitive, that's a **different design** than what Photonic implements. I flag this explicitly in §8.

---

## 1. Repo structure

**Workspace:** pnpm monorepo, `packages/{lib,app,cli}`. dMint lives almost entirely in `packages/lib`; CLI has **no** dMint support (confirmed by `grep -in dmint packages/cli/` → zero hits, plus `packages/cli/src/schemas.ts:8: // dmint not fully implemented yet`).

**Files that matter:**

| Path | Role |
|---|---|
| `packages/lib/src/contracts/powmint.rxd` | CashScript source for the PoW mint contract (authoritative spec of the covenant) |
| `packages/lib/src/script.ts` lines 442–766 | `dMintScript()` builder + helpers (`dMintDiffToTarget`, `buildDmintPreimageBytecodePartA`, `buildV2BytecodePartB`, `buildAsertDaaBytecode`, `buildLinearDaaBytecode`, plus the V2 bytecode constants) |
| `packages/lib/src/mint.ts` lines 368–484 | `createRevealOutputs` — deploy-tx construction path (how contract UTXOs are created alongside the glyph FT reveal) |
| `packages/lib/src/mint.ts` lines 200–217 | Commit output layout for dMint (reserves N extra p2pkh UTXOs for ref sequencing) |
| `packages/lib/src/types.ts` | `RevealDmintParams`, `DmintPayload`, `DmintAlgorithmId`, `DaaModeId` |
| `packages/lib/src/protocols.ts` | `GLYPH_DMINT = 4`; `PROTOCOL_REQUIREMENTS[DMINT] = [FT]` |
| `packages/lib/src/__tests__/dmint.test.ts` | Validates script encoding; asserts `OP_9 PICK`, `OP_13 PICK OP_13 PICK`, `OP_14 ROLL` for the 10-state V2 preimage |

**Not here:** the actual PoW solver / nonce grinder. Photonic Wallet **deploys** dMint contracts; mining them is the job of the external `glyph-miner` project. The deploy-side is fully in this repo; the mint-spend side is not.

**Surprise:** the CashScript source (`powmint.rxd`) and the hand-written hex builder (`dMintScript`) must be kept in sync; the V2 hex embeds `OP_BLAKE3`/`OP_K12` (0xee, 0xef), which the `.rxd` source does not express (it only has `hash256`). The `.rxd` file is v1 legacy reference; the **source of truth for v2 is the hex in `script.ts`**.

---

## 2. Mint-contract locking script — byte layout

A deployed dMint contract UTXO's `scriptPubKey` is built as `stateScript || 0xbd || contractBytecode`. The `0xbd` is `OP_STATESEPARATOR`. The same code bytecode is used by all dMint contracts for a given (algorithm, daaMode); only the state section differs per contract (so `codeScriptHash` is a useful index).

### 2.1 State script (V2, 10 items — `script.ts` lines 745–758)

Pushed in this exact order (all as script data pushes):

| # | Item | Push encoding | Bytes | Mutable? |
|---|---|---|---|---|
| 0 | `height` | `push4bytes(n)` = `04 <uint32_LE>` | 5 | **YES** (increments each spend) |
| 1 | `contractRef` (36B outpoint) prefixed `0xd8` | `0x25` (37-byte push) + `d8` + `<36B ref>` = literal `25 d8 <36B>` | 38 | no |
| 2 | `tokenRef` (36B outpoint) prefixed `0xd0` | `0x25` (37-byte push) + `d0` + `<36B ref>` | 38 | no |
| 3 | `maxHeight` | `pushMinimal(n)` | 1–6 | no |
| 4 | `reward` (per solve) | `pushMinimal` | 1–6 | no |
| 5 | `algoId` (0=sha256d, 1=blake3, 2=k12) | `pushMinimal` | 1 | no |
| 6 | `daaId` (0=fixed, 1=epoch, 2=asert, 3=lwma, 4=schedule) | `pushMinimal` | 1 | no |
| 7 | `targetTime` (seconds/block) | `pushMinimal` | 1–6 | no |
| 8 | `lastTime` | `push4bytes` = `04 <uint32_LE>` | 5 | in some DAA modes |
| 9 | `target` (8-byte VmNumber) | `pushMinimal(bigint)` | 1–10 | in adaptive DAA modes |

**Important — why items 1 & 2 use `0xd8` / `0xd0` prefixes:** those are `OP_PUSHINPUTREFSINGLETON` (`0xd8`) and `OP_PUSHINPUTREF` (`0xd0`) opcodes. The whole 37-byte push is a **data push of the opcode + 36-byte outpoint**; those bytes will be interpreted as push-data inside the state script but the contract logic then **concatenates that 37-byte blob into the new state script on respend**, preserving the ref-declaration structure. This is the trick that makes the covenant work: ref opcodes appear in state-script as data, but they are copied verbatim into the rebuilt state and re-executed next time.

### 2.2 Separator

One byte: `0xbd` (`OP_STATESEPARATOR`).

### 2.3 Code bytecode — three concatenated parts

```
contractBytecode = PART_A  ||  powHashOp  ||  PART_B  ||  PART_C
```

where `PART_B = V2_B1 || V2_B2 || daaBytecode || V2_B4`.

#### PART A — preimage assembly (`buildDmintPreimageBytecodePartA`, lines 447–473)

With `stateItemCount = 10`, the indices are `contractRefPickIndex=9`, `inputOutputPickIndex=13`, `nonceRollIndex=14`.

Hex sequence:

```
51              OP_1                           (push 1 = `outputIndex` target pos)
75              OP_DROP
c8              OP_OUTPOINTTXHASH              (pushes this UTXO's prev-txid)
59              OP_9                           (PICK index for contractRef)
79              OP_PICK
7e              OP_CAT                         (txHash || contractRef)
a8              OP_SHA256                      (= sha256(outpoint.txid || contractRef))
5d              OP_13                          (PICK index for inputHash)
79              OP_PICK
5d              OP_13                          (PICK index for outputHash)
79              OP_PICK
7e              OP_CAT                         (inputHash || outputHash)
a8              OP_SHA256                      (= sha256(inputHash || outputHash))
7e              OP_CAT                         (first-sha256 || second-sha256)
5e              OP_14                          (ROLL index for nonce)
7a              OP_ROLL
7e              OP_CAT                         (full preimage: 32 + 32 + 4 = 68 bytes)
```

#### PoW hash opcode (1 byte, line 735–740)

| Algo | Opcode |
|---|---|
| sha256d | `0xaa` (`OP_HASH256`) |
| blake3 | `0xee` (`OP_BLAKE3`) |
| k12 | `0xef` (`OP_K12`) |

#### PART B.1 — hash → value extraction (line 616)

```
bc             OP_REVERSEBYTES
01 14          push 0x14 (= 20)
7f             OP_SPLIT         → [first20, last12]
77             OP_NIP           → drop first20 → stack top: last12
58             OP_8
7f             OP_SPLIT         → [next8, firstFour]
04 00000000    push 4-byte zero
88             OP_EQUALVERIFY   → require firstFour == 00000000
81             OP_NEGATE
76             OP_DUP
00             OP_0
a2             OP_GREATERTHANOREQUAL
69             OP_VERIFY
               → "dup, push 0, ≥, VERIFY" = require value >= 0
```

So B.1 byte-for-byte: `bc 01 14 7f 77 58 7f 04 00000000 88 81 76 00 a2 69`

#### PART B.2 — target check (line 618)

```
51  OP_1
79  OP_PICK     (pick target from state)
7c  OP_SWAP     ([value, target])
a2  OP_GREATERTHANOREQUAL   (target ≥ value)
69  OP_VERIFY
```

**Literal:** `51797ca269`.

#### DAA bytecode — conditional, 0 bytes for `fixed`

For `asert` (`buildAsertDaaBytecode`, lines 627–666) — ~50 bytes of ops using `OP_TXLOCKTIME (c5)`, OP_SUB, OP_DIV, clamping, OP_LSHIFT/RSHIFT on target.

For `lwma` (Linear DAA, lines 668–685) — ~15 bytes, `new_target = old_target * time_delta / targetTime`, clamp ≥ 1.

For `fixed` / `epoch` / `schedule` — empty string (treated as fixed at the contract level; schedule would be enforced by the miner presumably).

#### PART B.4 — cleanup (line 620)

Hex: `7575757575` — five `OP_DROP` to pop the 5 V2 extras.

#### PART C — output validation (line 622)

**This is the covenant.** It's 177 bytes, partially hand-coded, literal:

```
a2 69                   (≥, VERIFY — residual)
57 7a e5 00 a0 69       require inputs.codeScriptCount(inputHash) > 0
56 7a e6 00 a0 69       require outputs.codeScriptCount(outputHash) > 0
01 d0 53 79 7e          push 0xd0, OP_3 PICK tokenRef, OP_CAT
0c dec0e9aa76e378e4a269e69d 7e   push 12-byte FT code suffix, OP_CAT
aa                      OP_HASH256 → rewardCSH
76                      OP_DUP
e4                      OP_CODESCRIPTHASHVALUESUM_OUTPUTS
7b                      OP_ROT
9d                      OP_NUMEQUALVERIFY   — require reward_sum == REWARD
54 7a 81 8b             OP_4 OP_ROLL OP_NEGATE OP_ADD1  (heightBytes → newHeight)
76 53 7a 9c             OP_DUP OP_3 PICK OP_NUMEQUAL
53 7a de 78 91 81       OP_3 PICK OP_CODESCRIPTHASHOUTPUTCOUNT...
54 7a e6 93 9d          OP_4 OP_ROLL OP_CODESCRIPTHASHOUTPUTCOUNT_OUTPUTS OP_ADD OP_NUMEQUALVERIFY
63                      OP_IF (finalMint branch)
  52 79 cd              OP_2 PICK OP_OUTPUTBYTECODE
  01 d8 53 79 7e        push 0xd8, OP_3 PICK contractRef, OP_CAT
  01 6a 7e              push 0x6a (OP_RETURN), OP_CAT
  88                    OP_EQUALVERIFY  — burn
67                      OP_ELSE (normal branch, recreate contract)
  78 de 51 9d           OP_SWAP OP_CODESCRIPTHASHOUTPUTCOUNT == 1
  54 78 54 80 7e        OP_4 ROLL newHeight, build 04||<4 bytes newHeight>
  c0 eb 55 7f 77        OP_INPUTINDEX OP_STATESCRIPTBYTECODE_UTXO OP_5 OP_SPLIT OP_NIP
  7e                    OP_CAT   → newState = 04||<newHeight>||<rest of state>
  53 79 ec              OP_3 PICK OP_STATESCRIPTBYTECODE_OUTPUT
  78 88                 OP_SWAP OP_EQUALVERIFY  — stateScript == newState
  53 79 ea c0 e9 88     OP_3 PICK OP_CODESCRIPTBYTECODE_OUTPUT OP_INPUTINDEX OP_CODESCRIPTBYTECODE_UTXO OP_EQUALVERIFY
  53 79 cc 51 9d        OP_3 PICK OP_OUTPUTVALUE OP_1 OP_NUMEQUALVERIFY  — value == 1
  75 68                 OP_DROP OP_ENDIF
6d 75 51                OP_2DROP OP_DROP OP_1
```

**Literal hex** (the authoritative bytes Photonic ships):

```
a269577ae500a069567ae600a06901d053797e0cdec0e9aa76e378e4a269e69d7eaa76e47b9d547a818b76537a9c537ade789181547ae6939d635279cd01d853797e016a7e886778de519d547854807ec0eb557f777e5379ec78885379eac0e9885379cc519d75686d7551
```

### 2.4 Mutable state slot

The **only** mutable byte-offset in the state script is item 0 (`height`), at the very start. Every spend:
1. Reads current `height` (4 LE bytes at offset 1, after the `0x04` push-length prefix).
2. Increments it to produce `newHeight`.
3. Builds `newState = 0x04 || <newHeight LE32> || <original state script bytes 5..end>`.
4. Asserts output's state script equals `newState`.

So the covenant only mutates `height`; everything else (refs, maxHeight, reward, algo, daa params, target) is frozen — including `target`, meaning in `fixed` DAA the difficulty never changes. For adaptive DAA (asert/lwma) the `target` is recomputed but since the state-script copy is `split(5)[1]` (preserves bytes 5..end verbatim), the **only way** `target` could actually mutate would be via a different rebuild formula. Looking at the literal C part: the rebuild uses `OP_5 SPLIT NIP` (byte 5 onward copied verbatim), so in Photonic's implementation **even asert/lwma DAA does not actually mutate the stored target** — the DAA bytecode computes a new value that's used *within* the current spend but isn't persisted. This may be a simplification; a full adaptive-DAA dMint would need to persist new target + lastTime. Flag for pyrxd authors: **audit this against REP-3010 before claiming asert/lwma DAA works end-to-end**.

---

## 3. Parameter encoding

| Parameter | Type | Encoding | Notes |
|---|---|---|---|
| `height` | uint32 | 4-byte LE, explicit `0x04` push prefix (`push4bytes`) | fixed width — covenant splits at byte 5 |
| `contractRef` | 36-byte outpoint | 37-byte push: `d8` + 36 bytes; raw bytes reversed-endian per `Outpoint.reverse()` | "NOTE: All ref inputs for script functions must be little-endian" (`script.ts:16`) |
| `tokenRef` | 36-byte outpoint | 37-byte push: `d0` + 36 bytes; little-endian | same |
| `maxHeight` | int | minimal push (OP_0..OP_16 or len-prefixed) | via `pushMinimal` |
| `reward` | int (photons) | minimal push | |
| `algoId` | byte | minimal push (OP_0..OP_2) | 0=sha256d, 1=blake3, 2=k12; higher (argon2, randomx) defined but not wired |
| `daaId` | byte | minimal push (OP_0..OP_4) | |
| `targetTime` | int (seconds) | minimal push | default 60 |
| `lastTime` | uint32 | 4-byte LE push | used by asert/lwma |
| `target` | bigint (signed VM number, ≤ `0x7fffffffffffffff`) | minimal VM-number push via libauth `bigIntToVmNumber` | `MAX_TARGET = 0x7fffffffffffffffn`, `target = MAX_TARGET / difficulty` |

An outpoint ref is `<32-byte txid>||<4-byte vout>` — reversed to little-endian on the way into the script. `Outpoint.reverse().ref()` is the canonical transform in Photonic (see `mint.ts:406-408`).

---

## 4. Deploy-tx construction

### 4.1 Two-phase commit/reveal

Glyph v2 tokens are deployed via **commit → reveal** (not dMint-specific; all glyphs work this way). The commit tx locks a small p2sh-ish output whose script includes `hash256(payload)` check + glyph magic `gly`. The reveal tx spends that commit UTXO, pushing the raw payload in the scriptSig so verifiers can hash it and confirm.

### 4.2 dMint-specific commit outputs (`mint.ts:203-209`)

When `deployMethod === "dmint"` and `contract === "ft"`:
- Commit tx emits the standard FT commit output at `vout[0]` (value 1).
- Then **N extra p2pkh outputs** (N = `numContracts`) at `vout[1..N]`, value 1 each. Each of these is a **ref seed** — spending it in the reveal tx creates a new input-ref that becomes a `contractRef`.

### 4.3 Reveal tx (`mint.ts:398-461`)

Inputs:
- `[0]` = commit UTXO (FT commit, scriptSig pushes the payload)
- `[1..N]` = the N p2pkh ref-seed UTXOs from the commit tx, spent with p2pkh signatures

Outputs (order matters):
- `[0..N-1]` = N dMint contract UTXOs, value 1 each, script = `dMintScript(height=0, contractRef=Outpoint(commit.txid, 1+i), tokenRef=Outpoint(commit.txid, 0), …)`
- `[N]` (optional) = premine FT output with script = `ftScript(address, tokenRef)` and value = `premine`.

`Outpoint` is reversed (LE) before embedding — see `mint.ts:406-408`: `Outpoint.fromUTXO(txid, vout+1+i).reverse().ref()`.

### 4.4 Ref establishment

The `tokenRef` (the permanent FT identity) = reversed outpoint of the commit tx's vout 0, established the moment the reveal tx confirms.

Each `contractRef[i]` = reversed outpoint of commit tx's vout (1+i), "minted" by the reveal tx consuming that p2pkh output and creating output `i` with `OP_PUSHINPUTREFSINGLETON <contractRef[i]>` in its state.

**This is subtle:** the reveal tx doesn't explicitly push ref opcodes in *its own* output scripts — the ref opcodes live *inside state script pushes* (items 1 and 2 above). Radiant's ref machinery recognizes `d8<36B>` and `d0<36B>` as ref declarations wherever they appear in a script. Because `OP_STATESEPARATOR` divides state from code, and refs declared pre-separator still bind to the UTXO, this works.

---

## 5. Mint-spend tx construction (the "mining" transaction)

Photonic does **not** implement this (CLI has no dmint, app only deploys). Reconstructed from `powmint.rxd` + script layout:

### 5.1 scriptSig (consuming a dMint contract UTXO)

scriptSig pushes (bottom-to-top):
1. `<outputIndex>` — the vout index in this spend where the recreated contract UTXO lives
2. `<outputHash>` — codeScriptHash of some expected output
3. `<inputHash>` — codeScriptHash of some expected input
4. `<nonce>` — 4 bytes

### 5.2 Output layout for a mint spend

- `output[outputIndex]` = recreated dMint contract UTXO with incremented `height`. Value = 1.
- One or more outputs with the **reward FT code-script** totaling `reward` photons of value. The miner chooses the state-script prefix (e.g. their own p2pkh), making them the effective owner.
- On final mint (height+1 == maxHeight), instead of recreating the contract, output[outputIndex] = `0xd8 || contractRef || 0x6a` (unspendable burn).

### 5.3 Single-tx, not commit/reveal

dMint spending is **one tx**: spend contract UTXO → produce FT reward + new contract UTXO. No commit/reveal on the mint path. Commit/reveal is only on initial **deploy**.

---

## 6. Covenant enforcement — which opcodes

Radiant-specific opcodes used by the PoW covenant:

| Opcode | Hex | Purpose |
|---|---|---|
| `OP_STATESEPARATOR` | `bd` | Separates mutable state from code-script hash |
| `OP_PUSHINPUTREF` | `d0` | Declares a "normal" ref (FT-style) |
| `OP_PUSHINPUTREFSINGLETON` | `d8` | Declares a "singleton" ref (NFT-style — the contract itself) |
| `OP_STATESCRIPTBYTECODE_UTXO` | `eb` | Gets current input's state script |
| `OP_STATESCRIPTBYTECODE_OUTPUT` | `ec` | Gets an output's state script |
| `OP_CODESCRIPTBYTECODE_UTXO` | `e9` | Gets current input's code script |
| `OP_CODESCRIPTBYTECODE_OUTPUT` | `ea` | Gets an output's code script |
| `OP_OUTPUTBYTECODE` | `cd` | Gets full output locking bytecode |
| `OP_OUTPOINTTXHASH` | `c8` | Gets txid of this input's outpoint |
| `OP_CODESCRIPTHASHVALUESUM_OUTPUTS` | `e4` | Sum values of outputs matching a code-script hash |
| `OP_CODESCRIPTHASHOUTPUTCOUNT_OUTPUTS` | `e6` | Count outputs matching a code-script hash |
| `OP_REFOUTPUTCOUNT_OUTPUTS` | `de` | Count outputs that declare a given ref |
| `OP_TXLOCKTIME` | `c5` | Current tx's locktime (used by asert DAA) |
| `OP_BLAKE3` | `ee` | Blake3 hash (V2 hard fork) |
| `OP_K12` | `ef` | KangarooTwelve hash (V2 hard fork) |

The "spend-and-recreate" invariant is enforced by PART C using:
- `OP_STATESCRIPTBYTECODE_OUTPUT` + `OP_EQUALVERIFY` — new state must equal computed `newState`
- `OP_CODESCRIPTBYTECODE_OUTPUT` vs `OP_CODESCRIPTBYTECODE_UTXO` + `OP_EQUALVERIFY` — code script frozen
- `OP_OUTPUTVALUE == 1` — UTXO dust value fixed
- `OP_REFOUTPUTCOUNT_OUTPUTS(contractRef) == 1` — singleton contract ref appears in exactly one output

For reward enforcement:
- `OP_CODESCRIPTHASHVALUESUM_OUTPUTS(rewardCSH) == REWARD` — exactly `REWARD` photons land in FT outputs
- `rewardCSH = hash256(d0 || tokenRef || dec0e9aa76e378e4a269e69d)` (computed in-script)

For final-mint burn:
- `tx.outputs[outputIndex].lockingBytecode == 0xd8 || contractRef || 0x6a` — contract burns itself to unspendable OP_RETURN output.

---

## 7. Gotchas & design decisions

1. **Ref endianness.** All refs in scripts are **little-endian** reversed outpoints. Python will need an `Outpoint.reverse_le()` helper.
2. **Minimal pushes are mandatory.** Test `hasNonMinimalDataPush` rejects any data push that should've been OP_0..OP_16.
3. **VmNumber encoding** (for `target`, `maxHeight`, etc. when > 16): signed little-endian with sign bit in the high byte; length is minimal.
4. **Fixed-width `height` is load-bearing.** The covenant does `OP_5 SPLIT NIP` to preserve bytes 5..end of the old state, so `height` MUST be pushed as exactly `04 <4 bytes LE>` (5 bytes total). Don't use `pushMinimal` for height.
5. **Same for `lastTime`** — also pushed as `push4bytes` for the same reason if DAA code reads it at a fixed offset.
6. **codeScriptHash calculation**: `hash256` in Radiant Script = SHA256(SHA256(x)). In Python: `hashlib.sha256(hashlib.sha256(code_bytes).digest()).digest()`.
7. **`OP_BLAKE3` / `OP_K12` activation.** V2 hard fork, block 410,000. Contracts deployed before activation will not be mineable.
8. **Script size.** With 10 state items, typical state script ≈ 100–130 bytes; code bytecode ≈ 250 bytes (fixed DAA) up to ~310 (asert). Total locking script well under the 10 kB standardness limit.
9. **Target packing.** `MAX_TARGET = 0x7fffffffffffffffn` (63-bit, since VmNumber is signed and must be positive). `target = MAX_TARGET // difficulty`.
10. **No authorized-minter field.** If you need gated minting, you'd layer a `OP_CHECKSIG` requirement on the contract — not present in Photonic's dMint.
11. **"Mint contract destroyed" is NOT the same as "supply exhausted".** `maxHeight * reward` is the theoretical max per contract; if a miner never produces the final spend, some supply is orphaned. Premine is fully minted at deploy time.
12. **Batch deploy with `numContracts > 1`** multiplies effective mint rate. Each contract mines independently; all share the same `tokenRef` so their FT outputs are fungible.

---

## 8. Ready-to-port API sketch for pyrxd

```python
# pyrxd/glyph/dmint.py

from dataclasses import dataclass
from enum import IntEnum
from typing import Optional, Literal

class DmintAlgo(IntEnum):
    SHA256D = 0
    BLAKE3 = 1
    K12 = 2
    # 3 (Argon2Light) / 4 (RandomX) reserved; not wired in Photonic

class DaaMode(IntEnum):
    FIXED = 0
    EPOCH = 1
    ASERT = 2
    LWMA = 3
    SCHEDULE = 4

@dataclass
class DaaParams:
    target_block_time: int = 60
    half_life: Optional[int] = None       # asert
    window_size: Optional[int] = None     # lwma
    epoch_length: Optional[int] = None    # epoch
    max_adjustment: Optional[int] = None  # epoch
    schedule: Optional[list[tuple[int, int]]] = None  # [(height, difficulty), ...]

def dmint_contract_locking_script(
    height: int, contract_ref: bytes, token_ref: bytes,
    max_height: int, reward: int, target: int,
    algo: DmintAlgo = DmintAlgo.SHA256D,
    daa_mode: DaaMode = DaaMode.FIXED,
    daa_params: Optional[DaaParams] = None,
    last_time: int = 0,
) -> bytes:
    """Build a dMint PoW-mint contract locking script per Glyph v2 (REP-3010)."""
    ...

def dmint_difficulty_to_target(difficulty: int) -> int:
    """MAX_TARGET // difficulty, where MAX_TARGET = 0x7fffffffffffffff."""
    return 0x7fffffffffffffff // difficulty
```

**Open questions for pyrxd design:**
- Do you want *Photonic-style PoW dMint*, or *the gated-minter dMint sketched in the research prompt*? These are different primitives. Photonic = REP-3010 = what's deployed on mainnet today.
- Do you need on-chain adaptive DAA (asert/lwma)? Photonic's implementation may not actually persist updated `target` across spends (see §2.4 note). `fixed` mode is the safe default.
- Will pyrxd ship its own PoW solver (nonce grinder)? Photonic doesn't — it relies on the external `glyph-miner`. Grinding sha256d at Python speed is ~200k H/s on a CPU — usable for tiny difficulty, useless above ~10^6.

---

## 9. Premine mint feasibility

**TL;DR: Yes — Photonic's dMint *already* supports this. A `premine` field on the deploy tx creates an FT output holding any amount (up to and including full supply) in the issuer's wallet at deploy time, outside the covenant.**

### 9.1 The `premine` field is a first-class, unconstrained parameter

`packages/lib/src/types.ts:68-78` defines `RevealDmintParams` with `premine: number` as a required field. The covenant never reads it. It is purely a reveal-tx output amount.

`packages/lib/src/mint.ts:430-439` is the entire implementation:

```ts
if (dmintParams.premine > 0) {
  outputs.push({
    script: ftScript(deployParams.address, tokenRef),
    value: dmintParams.premine,
  });
}
```

No bounds checks on `premine` anywhere: no `require(premine <= maxHeight * reward)`, no protocol-level supply cap.

### 9.2 Recommended premine-only configuration

| field | value | why |
|---|---|---|
| `premine` | `TOTAL_SUPPLY` | all tokens land in issuer's wallet at deploy |
| `numContracts` | `1` | one orphan covenant; never spent |
| `maxHeight` | `1` | only valid spend is the `finalMint` burn path |
| `reward` | `0` | even if somehow spent, no new tokens emit |
| `difficulty` | `1` | irrelevant — contract UTXO just sits there |

The dMint covenant UTXO is still created but **no one ever needs to spend it**. It sits at dust value forever. Your entire supply is in the `ftScript` premine output, transferable like any FT.

**You do not need to "burn" or "finalize" the covenant.** Unspent dMint UTXOs are harmless. Belt-and-braces: setting `maxHeight = 1` with initial `height = 0` means the first (and only) valid spend is forced through the `finalMint` branch, which requires the output to be `0xd8 + contractRef + 0x6a` — an unspendable OP_RETURN-style burn. Combined with `reward = 0`, even that hypothetical spend emits zero tokens.

### 9.3 Answers to specific sub-questions

1. **Premine code path exists:** yes, `mint.ts:430`.
2. **Does the covenant permit `amount == max_supply` in a single spend?** No through the covenant — `powmint.rxd:37` requires exactly `reward` tokens per mint. Premine bypasses the covenant entirely.
3. **Does PoW apply to the first mint?** Yes — every covenant spend must satisfy the 32-bit-zero-prefix floor. But the premine output is not a covenant spend, so PoW never gates it.
4. **A no-PoW dMint variant?** Not in the repo. V2 bytecode PART B1 hard-codes the 32-bit-zero-prefix floor.
5. **Fixed DAA at `target = MAX_TARGET`?** The 32-bit-zero floor is checked *before* the target comparison. So even `target = 0x7fffffffffffffff` still requires ~2^32 hashes. Not "PoW-free" — but cheap enough to work as a fallback.

### 9.4 Recommendation for pyrxd

Implement dMint in pyrxd with `premine` as a first-class field, and document the "premine = total_supply, reward = 0, maxHeight = 1" pattern as the **fixed-supply FT issuance recipe**.

---

## 10. V1 vs V2 classification + ship decision

**Date:** 2026-04-22. Superseding guidance after reviewing live-mainnet decode evidence.

### 10.1 How classification actually works

**Classification is driven entirely by the CBOR payload's `p` array, not by the contract-script shape.** The covenant bytecode is functionally invisible to the indexer.

Evidence (Photonic Wallet HEAD):
1. `packages/lib/src/token.ts:58-131` (`decodeGlyph`) — scans for `gly` magic, then CBOR-decodes. Never examines the locking script.
2. `packages/app/src/electrum/worker/NFT.ts:379-418` (`saveGlyph`) — classifies strictly from `payload.p`.
3. `packages/lib/src/protocols.ts:67-82` (`getTokenType`) — derives from `p`: `"dMint FT"` when `[GLYPH_FT, GLYPH_DMINT]` both present.

**Conclusion:** a premine-only token carrying `p: [1, 4]` will be classified as "dMint FT" regardless of whether any covenant UTXO ever existed.

### 10.2 Where is V1 bytecode

**V1 bytecode IS archived in the current repo**, flagged as "legacy for backward-compatible parsing":

- `packages/lib/src/script.ts:624-625`: `V1_BYTECODE_PART_B` — a 125-byte literal. Structurally it equals `V2_PART_B1` + `a2` + `V2_PART_C`. V1 has no target-comparison PART_B2 and no stack-cleanup PART_B4.
- The authoritative V1 source of truth remains `packages/lib/src/contracts/powmint.rxd` (6 constructor params, 3 runtime state items).
- A V1 *constructor* is **not** in the repo. `dMintScript` unconditionally emits V2.

**Path to produce V1 bytes:** combine the mainnet decode's literal 241-byte template with the 3-state PART_A produced by `buildDmintPreimageBytecodePartA(3)`. Concatenate `stateScript(3 items) + 0xbd + PART_A(3) + 0xaa + V1_BYTECODE_PART_B`.

### 10.3 Ship recommendation: Option (d) with a hedge

**Recommendation: pyrxd 0.2 ships the premine-only deploy path with NO covenant UTXO. Set `numContracts = 0`.**

Rationale:
1. Classification is CBOR-only — covenant UTXO contributes nothing.
2. The covenant is dead weight for premine-only deploys.
3. No code in Photonic requires `numContracts >= 1`.
4. Avoids the V1/V2 tarpit entirely.

**Hedge:** if a downstream consumer is later found to require covenant-UTXO presence, ship V1 emission at that point. V1 is what 100% of deployed mainnet contracts use.

**Do not ship V2 emission in pyrxd 0.2.** V2 matches no deployed contract.

---
---

# Part II — V1 dMint Contract Research: Radiant Mainnet

**Date:** 2026-04-22

Reverse-engineering notes for pyrxd's dMint builder. All on-chain data was pulled directly from a Radiant full node; every hex string and txid below was copied out of that node's RPC output.

---

## 1. Discovery method

- **MCP tool list**: `radiant_get_dmint_contracts` / `radiant_get_dmint_contract` — public ElectrumX returned `unknown method`, dead end.
- **Direct node access**: fell back to `radiant-mainnet` container (block height 422,868). Scanned from tip backward looking for scriptPubKey outputs containing the dMint epilogue fingerprint `dec0e9aa76e378e4`.
- **Reference implementation**: `/tmp/photonic-wallet/packages/lib/src/script.ts` (`dMintScript`, lines 440–766).

A 200-block scan yielded 31 live dMint contract UTXOs. A second targeted scan (stop after 7 distinct contract refs) is the basis for the contracts listed below.

---

## 2. Contracts found

All seven distinct contract UTXOs come from a **single token deployment**: commit tx `a443d9df…878b`.

- **Deploy commit txid**: `a443d9df469692306f7a2566536b19ed7909d8bf264f5a01f5a9b171c7c3878b` (35 outputs; vouts 0 and 33 are Glyph hashlock commits, vouts 1–32 are P2PKH seed outputs)
- **Permanent token ref**: `8b87c3c771b1a9f5015a4f26bfd80979ed196b5366257a6f30929646dfd943a400000000` (commit txid at vout 0)
- **Algorithm**: `OP_HASH256` (byte `0xaa`) → sha256d
- **DAA mode**: none → **fixed** difficulty
- **Mining state item count**: 3 state items (height, maxHeight, reward + 8-byte target). This is the **V1 dMint template**, not the 10-item V2 template.

### 2.1 Contract UTXO inventory (seven sampled instances)

| # | Contract UTXO (unspent sample) | contractVout | Script hex (all 241 bytes) |
|---|--------------------------------|:-:|--|
| 1 | `f0a6a106135ddb1072910f7bc4849b04a7117d832d3643c8d9d98185fb543b0d:0` | 1 | `04de5f0100d88b87c3c771b1a9f5015a4f26bfd80979ed196b5366257a6f30929646dfd943a401000000d08b87c3c771b1a9f5015a4f26bfd80979ed196b5366257a6f30929646dfd943a400000000036889090350c3000874da40a70d74da00bd5175c0c855797ea8597959797ea87e5a7a7eaabc01147f77587f040000000088817600a269a269577ae500a069567ae600a06901d053797e0cdec0e9aa76e378e4a269e69d7eaa76e47b9d547a818b76537a9c537ade789181547ae6939d635279cd01d853797e016a7e886778de519d547854807ec0eb557f777e5379ec78885379eac0e9885379cc519d75686d7551` |
| 2 | `cb273c1ea1025a93b7ec08eedae29fc2285a820a4d29765027035a9fa7b926b3:0` | 4 | identical suffix from byte 79 on |
| 3 | `f0cfc00173629680540b071ee2d5e86e2d86037f9fa947d087a2f3f7901d0964:0` | 8 | identical suffix from byte 79 on |
| 4 | `bec0eae1706029d053357114dd17aab8510efc0b1e0b870a620726d221aa9fd5:0` | 11 | identical suffix from byte 79 on |
| 5 | `9a08f4025c48c32b3e156e4f949f8bae7136266299c9d1335f6ec167666eb031:0` | 12 | identical suffix from byte 79 on |
| 6 | `a4709d7e125789276c6e95d668b1db307ec4f5d5223abf5c363b74aef912b955:0` | 13 | identical suffix from byte 79 on |
| 7 | `a86c134f8a34a4a0bbf5530090e728888fc8d9b7cee1c59f0270cbe7bd6b8bc7:0` | 28 | identical suffix from byte 79 on |

### 2.2 Byte-by-byte decode of UTXO #1

`scriptPubKey` of `f0a6a106…3b0d:0` (241 bytes total):

| Offset | Bytes | Opcode | Decoded meaning |
|-------:|-------|--------|-----------------|
| 0 | `04 de5f0100` | OP_PUSH4 | **height** = 0x00015fde = 90,078 |
| 5 | `d8 8b87…943a4 01000000` | OP_PUSHINPUTREFSINGLETON | **contractRef** (vout 1 of commit tx) |
| 42 | `d0 8b87…943a4 00000000` | OP_PUSHINPUTREF | **tokenRef** (vout 0 of commit tx) |
| 79 | `03 688909` | OP_PUSH3 | **maxHeight** = 628,328 |
| 83 | `03 50c300` | OP_PUSH3 | **reward** = 50,000 photons |
| 87 | `08 74da40a70d74da00` | OP_PUSH8 | **difficulty target** = 0x00da740da740da74 LE |
| 96 | `bd` | OP_STATESEPARATOR | End of state, start of contract bytecode |
| 97 | `51 75` | OP_1 OP_DROP | Opening frame marker |
| 99 | `c0` | OP_INPUTINDEX | |
| 100 | `c8` | OP_OUTPOINTTXHASH | |
| 101 | `55 79` | OP_5 OP_PICK | Pick contractRef |
| 103 | `7e a8` | OP_CAT OP_SHA256 | Hash(outpointTxHash ‖ contractRef) |
| 105 | `59 79 59 79` | OP_9 OP_PICK ×2 | Pick inputHash and outputHash |
| 109 | `7e a8 7e` | OP_CAT OP_SHA256 OP_CAT | Fold both hashes |
| 112 | `5a 7a` | OP_10 OP_ROLL | Roll the nonce |
| 114 | `7e` | OP_CAT | Concat nonce → final preimage |
| 115 | `aa` | **OP_HASH256** | **PoW hash** — sha256d |
| 116 | `bc 0114 7f 77` | OP_REVERSEBYTES PUSH(0x14) OP_SPLIT OP_NIP | Drop top 20 bytes |
| 121 | `58 7f` | OP_8 OP_SPLIT | Split off leading 8 bytes |
| 123 | `04 00000000 88` | PUSH(4 zeros) OP_EQUALVERIFY | Require top 4 reversed bytes = zero |
| 129 | `81 76 00 a2 69 a2 69` | Target-comparison epilogue | pow-hash low 8 bytes ≤ target |
| 136 | `57 7a e5 00 a0 69` | ≥1 input with matching codescript hash |
| 142 | `56 7a e6 00 a0 69` | ≥1 output with matching codescript hash |
| 148 | `01 d0 53 79 7e 0c dec0e9aa76e378e4a269e69d 7e aa` | Build expected code-script prefix, HASH256 |
| 168 | `76 e4 7b 9d` | **FT conservation** — sum of output photons == reward |
| 172 | `54 7a 81 8b` | Verify new height = old-height + 1 |
| 176 | `76 53 7a 9c 53 7a de 78 91 81 54 7a e6 93 9d` | Branch: singleton-continue vs burn |
| 191 | `63 … 67 … 68` | OP_IF / OP_ELSE / OP_ENDIF | 46 bytes: if mintable → recreate; else → burn |
| 238 | `6d 75 51` | OP_2DROP OP_DROP OP_1 | Final cleanup |

Total: **241 bytes**, **131 opcodes**.

### 2.3 Parameter values extracted from UTXO #1

| Parameter | Value | Source |
|-----------|-------|--------|
| height | 90,078 | state offset 0, 4-byte LE |
| contractRef | `8b87…943a4 \| 01000000` | state offset 5, 36 bytes |
| tokenRef | `8b87…943a4 \| 00000000` | state offset 42, 36 bytes |
| maxHeight | 628,328 | state offset 79, 3-byte LE |
| reward | 50,000 photons | state offset 83, 3-byte LE |
| target | `0x00da740da740da74` | state offset 87, 8-byte LE |
| difficulty (derived) | ≈ 150 | ESTIMATED: `0x7fffffffffffffff / target` |
| algorithm | sha256d | byte 115 = `0xaa` |
| DAA mode | fixed | no DAA bytecode |

The seven sampled UTXOs diverge only on height and contractRef-vout; all other parameters are identical. The contract is **mid-mint**: roughly 12–15% of the token's supply minted.

---

## 3. Cross-comparison

**Common template** (byte-identical across all seven, offsets 79–240):

```
03 688909 03 50c300 08 74da40a70d74da00
bd
5175 c0c8 5579 7ea8 5979 5979 7ea8 7e 5a7a 7e
aa
bc01147f77587f 04 00000000 88
8176 00a269 a269
577a e500a069 567a e600a069
01d0 5379 7e 0c dec0e9aa76e378e4a269e69d 7e aa
76 e47b9d
547a 818b
76 537a 9c 537a de 78 91 81 547a e6 93 9d
63 5279 cd 01d8 5379 7e 01 6a 7e 88
67
78 de 51 9d 54 78 54 80 7e c0 eb 55 7f 77 7e
53 79 ec 78 88 53 79 ea c0 e9 88 53 79 cc 51 9d
75 68
6d 75 51
```

**Mutable slots**: only offset 1–4 (`height`, 4 B LE, incremented by 1 each mint). Everything else is static for the contract's lifetime.

---

## 4. Trace of a single mint transaction

**Target mint tx**: `146a4d688ba3fc1ea9588e406cc6104be2c9321738ea093d6db8e1b83581af3c` (block 422,865)

### Inputs

- **vin[0]** — spends previous contract UTXO `8d318fba…fac5:0`. scriptSig (72 bytes): `[nonce=0x17f15897, inputHash=09b5…0a2, outputHash=4c3a…1a6, OP_0]`
- **vin[1]** — spends `8d318fba…fac5:3`, plain P2PKH. scriptSig = `<sig> <pubkey>` (106 bytes)

### Outputs

- **vout[0]** — 1 photon, 241-byte recreated dMint contract with height bumped by 1
- **vout[1]** — 0.0005 RXD (50,000 photons), 75-byte P2PKH-wrapped FT output: `p2pkh(miner_pkh) || bd || d0||tokenRef || dec0e9aa76e378e4a269e69d`
- **vout[2]** — OP_RETURN with mint marker
- **vout[3]** — change P2PKH

### What a Python implementation must reproduce

1. Build vout[0]'s 241-byte locking script with the **next** height value.
2. Build vout[1]'s 75-byte FT output = `p2pkh(pkh) || bd || d0||tokenRef || de c0 e9 aa 76 e3 78 e4 a2 69 e6 9d`.
3. The mint input's scriptSig provides `[nonce, inputHash, outputHash, OP_0]`.
4. The `reward` parameter must equal the FT output's value — enforced by `OP_CODESCRIPTHASHVALUESUM_OUTPUTS OP_NUMEQUALVERIFY`.

---

## 5. Open questions

- **Deploy reveal TX not yet isolated.** The commit is `a443d9df…878b`, but a backward walk from a recent mint (20 hops) did not reach the reveal.
- **Cannot distinguish V1 vs V2 encoding from the guide alone.** The guide ships V2 10-state-item layout. Live contracts are V1 3-state-item. A Python builder needs both code paths.
- **Nonce width and inputHash / outputHash construction** are only inferable from the unlock-side test vector.
- **Difficulty value 150 is ESTIMATED.** Derived by applying Photonic's `dMintDiffToTarget` formula.
- **Ticker "snk".** Based on string literal inside OP_RETURN markers, not authoritative.

---
---

# Part III — V1 Deploy: Mainnet Truth + Photonic Divergence

**Date:** 2026-05-08

Research notes for pyrxd's M2 (V1 deploy support). All on-chain data pulled from `wss://electrumx.radiant4people.com:50022/`.

---

## 1. Reference deployment: Glyph Protocol (GLYPH)

The only mainnet V1 dMint deploy located so far is RBG's "Glyph Protocol" deployment.

| Field | Value | Source |
|---|---|---|
| Deploy commit txid | `a443d9df469692306f7a2566536b19ed7909d8bf264f5a01f5a9b171c7c3878b` | from chain (h=228604) |
| Deploy reveal txid | `b965b32dba8628c339bc39a3369d0c46d645a77828aeb941904c77323bb99dd6` | from chain (h=228604) |
| Reveal raw size | 79,141 bytes | from chain |
| Reveal vin × vout | 36 × 35 | from chain |
| Token ticker | `GLYPH` | CBOR `ticker` field |
| Token name | `Glyph Protocol` | CBOR `name` field |
| Token description | `The first of its kind` | CBOR `desc` field |
| Protocol version | `p:[1,4]` | CBOR `p` field |
| numContracts | 32 | count of 241-byte contract outputs |
| maxHeight | 625,000 | bytes 80..82 of contract state |
| reward (sats) | 50,000 | bytes 84..86 of contract state |
| target (8 bytes BE) | `0x00da740da740da74` | bytes 88..95 of contract state |
| Total supply | 32 × 625,000 × 50,000 = 1,000,000,000,000 sats (10,000 GLYPH @ 8 decimals) | computed |
| Algorithm | sha256d (`OP_HASH256` / 0xaa) | epilogue PoW-hash opcode |
| DAA mode | none (fixed) | epilogue body shape |

These match Part II §2 exactly — the seven contract UTXOs sampled there were 7 of these 32.

---

## 2. Deploy commit shape (verified from chain)

The deploy commit `a443d9df…878b` has **35 outputs**, 1448 bytes total:

| vout | bytes | type | role |
|---:|---:|---|---|
| 0 | 75 | gly hashlock (≥1 ref) | **FT commit** — preimage on `vin 0` of reveal carries the FT body |
| 1–32 | 25 each | bare P2PKH | **32 ref-seeds** (one sat each) — each becomes a `contractRef[i]` |
| 33 | 75 | gly hashlock (≥2 refs) | **NFT commit** — preimage on `vin 33` of reveal |
| 34 | 25 | bare P2PKH | change |

### 2.1 The 75-byte hashlock shape

```
OP_HASH256 <32-byte payload-hash> OP_EQUALVERIFY
PUSH(3) "gly" OP_EQUALVERIFY
OP_INPUTINDEX OP_OUTPOINTTXHASH OP_INPUTINDEX OP_OUTPOINTINDEX
OP_4 OP_NUM2BIN OP_CAT OP_REFTYPE_OUTPUT OP_<N> OP_NUMEQUALVERIFY
OP_DUP OP_HASH160 PUSH(20) <20-byte pkh> OP_EQUALVERIFY OP_CHECKSIG
```

- **FT commit (vout 0)**: `OP_1` (0x51) — require ≥1 ref output
- **NFT commit (vout 33)**: `OP_2` (0x52) — require ≥2 ref outputs

### 2.2 No delegate-ref prefix

Both 75-byte scripts start at offset 0 with `aa 20` (`OP_HASH256` then PUSH(32)). No delegate-ref prefix present.

---

## 3. Deploy reveal shape (verified from chain)

Reveal `b965b32d…9dd6` has **36 inputs** and **35 outputs**:

### 3.1 Inputs

| vin | spends | role |
|---:|---|---|
| 0 | `a443d9df:0` (FT commit hashlock) | scriptSig (65,685 bytes) carries `<sig> <pubkey> <FT-preimage with CBOR+PNG>` |
| 1–32 | `a443d9df:1..32` (32 ref-seeds) | plain `<sig> <pubkey>` per P2PKH |
| 33 | `a443d9df:33` (NFT commit hashlock) | scriptSig (168 bytes) carries auth NFT preimage |
| 34 | prior mutable container NFT singleton | brings auth NFT identity in from a prior mint |
| 35 | `a443d9df:34` (change P2PKH) | funds the reveal fee |

### 3.2 Outputs

| vout | bytes | role |
|---:|---:|---|
| 0–31 | 241 each | **32 V1 dMint contract UTXOs** — each with `contractRef[i] = a443d9df:<i+1>`, all sharing `tokenRef = a443d9df:0` |
| 32 | 63 | **FT NFT** (public-facing token marker) — `d8 <a443d9df:33-LE> 75 76a9 14 <pkh> 88ac` |
| 33 | 63 | **Auth/container NFT** — `d8 <874c3cce:0-LE> 75 76a9 14 <pkh> 88ac` |
| 34 | 25 | change P2PKH (~45.87 RXD) |

### 3.3 Contract UTXO state breakdown (vout 0 of reveal)

Verified byte-for-byte from chain. The 96-byte state portion:

```
[ 0..  4]  04 00 00 00 00          height = 0  (LE-4 push)
[ 5.. 41]  d8 8b87c3c7…943a4 01000000   d8 + contractRef = a443d9df:1
[42.. 78]  d0 8b87c3c7…943a4 00000000   d0 + tokenRef    = a443d9df:0
[79.. 82]  03 68 89 09             maxHeight = 625,000  (LE-3 push)
[83.. 86]  03 50 c3 00             reward = 50,000  (LE-3 push)
[87.. 95]  08 74 da 40 a7 0d 74 da 00   target = 0x00da740da740da74  (LE-8 push)
```

Byte 96 = `bd` (OP_STATESEPARATOR), bytes 97..240 = 145-byte V1 epilogue (sha256d, fixed difficulty, FT-wrapped reward).

This is **exactly** what `build_dmint_v1_contract_script` in M1 emits.

---

## 4. CBOR token body (vin 0 of reveal scriptSig)

```python
{
  "p":      [1, 4],                              # protocol = V1 dMint FT  ← REQUIRED
  "ticker": "GLYPH",
  "name":   "Glyph Protocol",
  "desc":   "The first of its kind",
  "by":     [CBORTag(64, <36-byte NFT singleton ref>)],
  "main":   {"t": "image/png", "b": CBORTag(64, <PNG bytes>)},
}
```

**Critical for M2:**
1. The CBOR `p` field is `[1, 4]` (V1 dMint FT). Must NOT emit a `v` field (that's V2).
2. **dMint parameters are NOT in the CBOR.** They live entirely inside the contract output scripts.
3. `by` carries the 36-byte ref of the NFT that "owns" / authenticates this deploy.
4. `main` carries the project's display image. Optional.

### 4.1 Auth NFT body (vin 33 of reveal scriptSig)

```python
{
  "p":   [2],                                # protocol = V2 NFT
  "loc": 0,
  "by":  [CBORTag(64, <NFT singleton ref>)],
}
```

For pyrxd M2: this is **deferred work**. The simpler path is to mint the auth NFT freshly inside the same deploy reveal.

---

## 5. Photonic Wallet source (canonical reference)

| File | Lines | What it does |
|---|---|---|
| `packages/lib/src/mint.ts:175–217` | `createCommitOutputs` | Builds commit-tx outputs |
| `packages/lib/src/mint.ts:364–484` | `createRevealOutputs` | Builds reveal-tx I/O |
| `packages/lib/src/script.ts:152–182` | `ftCommitScript` | 75-byte gly hashlock |
| `packages/lib/src/script.ts:184–213` | `nftCommitScript` | Same with `OP_2` |
| `packages/lib/src/script.ts:704–766` | `dMintScript` | **EMITS V2 ONLY** |
| `packages/lib/src/types.ts:62–78` | `DeployMethod`, `RevealDmintParams` | Params shape |

### 5.1 Photonic `RevealDmintParams` shape

```ts
type RevealDmintParams = {
  address: string;
  difficulty: number;
  numContracts: number;
  maxHeight: number;
  reward: number;
  premine: number;
  algorithm?: string;    // V2 only
  daaMode?: string;      // V2 only
  daaParams?: any;       // V2 only
};
```

For pyrxd M2 we drop the V2-only fields:

```python
@dataclass(frozen=True)
class DmintV1DeployParams:
    owner_address: Address
    num_contracts: int              # 1..256
    reward_sats: int                # ≤ 0xFFFFFF
    max_height: int                 # ≤ 0xFFFFFF
    target: int                     # 8-byte difficulty target
    ticker: str
    name: str
    description: str
    auth_nft_ref: bytes | None = None
    main_image: bytes | None = None
    main_image_mime: str | None = None
```

---

## 6. Auth NFT decision: forward-prior vs mint-fresh

The on-chain GLYPH deploy uses **forward-prior**: vin 34 spends an existing mutable-container NFT.

**Decision (pyrxd M2):** mint-fresh. Forward-prior is deferred work. RXinDexer accepts both shapes.

Deploy reveal layout (mint-fresh):

```
vin 0:    spend FT commit hashlock (CBOR FT body)
vin 1..N: spend N ref-seeds (P2PKH)
vin N+1:  spend NFT commit hashlock (CBOR NFT body, p:[2], by=<self>)
vin N+2:  spend change (P2PKH)

vout 0..N-1: N dMint contract UTXOs
vout N:      FT NFT (d8 <commit:0-LE> 75 P2PKH)
vout N+1:    auth NFT (d8 <commit:N+1-LE> 75 P2PKH)
vout N+2:    change
```

---

## 7. Photonic divergences (pyrxd-specific)

### 7.1 V1 contract output layout (RESOLVED IN M1)

`dMintScript()` in current photonic-wallet master only emits V2. pyrxd M1 already implemented `build_dmint_v1_contract_script`.

### 7.2 Premine handling

Photonic supports optional `premine`. On-chain GLYPH deploy did not use it. **Decision (M2):** skip premine support in first cut — deferred.

### 7.3 Delegate-ref commit prefix

**Decision (M2):** `delegate=None` always; defer.

### 7.4 Algorithm + DAA mode

**Decision (M2):** hardcode `algorithm = 'sha256d'`, no DAA.

### 7.5 V1 vs V2 protocol vector in CBOR

- V1: `p: [1, 4]` (no `v` field)
- V2: `v: 1, p: [2, 4]` (different keys)

---

## 8. Acceptance gates derived from this research

- **Synthetic vector**: build a tx with the same params as GLYPH and assert byte-identical output.
- **VPS testmempoolaccept**: relay the deploy reveal in `dryrun` mode.
- **Mainnet smoke**: deploy a small token to mainnet; verify it appears in RXinDexer.

---

## 9. Open questions remaining

1. **Reveal scriptSig stub size for fees.** The FT preimage push can be arbitrarily large (GLYPH carried a 65KB PNG).
2. **Joint NFT+FT V1 deploy** — filed as deferred work.
3. **Resume after partial broadcast** — just the saved `commit_txid` and `DmintV1DeployParams` is enough to deterministically reproduce the reveal.

---

## 10. Sources

### From chain (queried 2026-05-08)

- Deploy commit `a443d9df…878b` raw bytes — saved to `/tmp/dmint-m2-research/`
- Deploy reveal `b965b32d…9dd6` raw bytes
- Prior tx `874c3cce…d56a` (h=227767) — Glyph NFT commit/reveal predecessor
- Prior tx `6de766d7…3eaf` (h=228398) — mutable-container NFT mint

### From Photonic Wallet master

- `packages/lib/src/mint.ts:174–276` (commit builders)
- `packages/lib/src/mint.ts:362–484` (reveal builder)
- `packages/lib/src/script.ts:152–263` (commit/output script primitives)
- `packages/lib/src/script.ts:704–766` (dMintScript — V2-only)
- `packages/lib/src/types.ts:60–110`

### From pyrxd M1 work

- `src/pyrxd/glyph/dmint.py` — V1 builders, parsers, miner, verifier
- Part II of this document — original V1 contract decode

---

## 11. Phase 2a exit checklist

- [x] On-chain V1 deploy located, fetched, and decoded byte-by-byte.
- [x] Photonic source read in full and key divergences documented.
- [x] Auth NFT strategy decided (mint-fresh; forward-prior deferred).
- [x] Premine + delegate-ref decisions documented (both deferred).
- [x] Acceptance-test inputs derived (golden synthetic vector parameters identified).
- [x] Open questions logged with decisions or "deferred" tags.

---
---

# Part IV — Historical Follow-up (premine-only era)

> The section below was the original `DMINT_RESEARCH.md` document, written when
> pyrxd shipped only the premine-at-deploy path. It is retained for historical
> context. The status note at the top of this document supersedes it.

pyrxd 0.2.x implements the **premine-at-deploy** FT path. This section captures
what a future PoW-capable SDK would need to implement Photonic's full dMint
protocol, and why most consumers do not require it.

## What pyrxd 0.2.x implemented

- `GlyphMetadata.for_dmint_ft(...)` — metadata with `p:[1,4]`
- `GlyphBuilder.prepare_ft_deploy_reveal(...)` — reveal scripts for premine-at-deploy FT
- `FtUtxoSet.build_transfer_tx(...)` — conservation-enforcing FT transfer
- CBOR cross-decoder tests
- Deploy structural integration tests + VPS `testmempoolaccept` proof

The `p:[1,4]` marker tells indexers this token follows the dMint protocol. For
premine-only consumers the only relevant part is the **deploy shape** — a single
reveal output carrying the full supply.

## When premine-only is enough

A **premine-only** token mints the entire supply to a treasury wallet at deploy.
Distribution happens via plain FT transfers. No post-deploy minting occurs.

Using `p:[1]` alone (plain FT, no dMint marker) also works for the premine
shape. The choice between `[1]` and `[1,4]` is a downstream decision — `[1,4]`
reads as "this token participates in the dMint protocol family even if it never
uses the PoW phase."

## Implementing PoW dMint (original future contributor guide)

1. **Difficulty covenant script** — model after `pyrxd/gravity/covenant.py`.
2. **Mint tx builder** — `build_mint_tx(covenant_utxo, nonce, miner_pkh, fee_sats)`.
3. **Difficulty verification** — `OP_SHA256` of the serialized mint tx must be `<=` target.
4. **Tests** — unit tests with trivial target; VPS integration test against live covenant.

The Photonic Wallet TypeScript source is the reference implementation. pyrxd's
`cbor2`-based CBOR encoding already matches Photonic's payload format.
