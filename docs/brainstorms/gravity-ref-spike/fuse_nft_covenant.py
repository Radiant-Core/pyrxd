#!/usr/bin/env python3
"""Phase-1 NFT fusion: transform a generated standard SPV maker covenant (.rxd)
into the NFT variant. Reads the standard covenant on stdin, writes the
NFT-fused .rxd on stdout. Mirrors fuse_ft_covenant.py with the NFT deltas.

Deltas vs the standard covenant:
1. Constructor: ADD bytes36 REF, bytes32 expectedTakerNftHash,
   bytes32 expectedMakerNftHash, int nftCarrierValue; DROP takerRadiantPkh,
   totalPhotonsInOutput, makerPkh.
2. Shared preamble (before `return {`): the NFT hardening —
   - pushInputRefSingleton(REF)  (this carries the singleton ref => the NFT is
     HELD in the covenant; the covenant UTXO is `d8<ref><body>`; consensus
     conservation = the singleton ref present, no code-script weld).
   - require(tx.outputs.length == 1)                 output-count clamp
   - require(tx.outputs.refOutputCount(ref) == 1)    SOLE guard vs burn/clone
                                                     (consensus permits burn!)
   - require(tx.outputs[0].value == nftCarrierValue) pin (constructability;
                                                     replaces the dropped amount)
   NOTE: NO refValueSum (singleton has no amount).
3. finalize route -> hash256(output[0]) == expectedTakerNftHash.
4. forfeit route  -> hash256(output[0]) == expectedMakerNftHash.

IMPORTANT (transform-order contract): do NOT rename the contract here. The
downstream fuse_anywallet.py matches the literal `MakerCovenantFlat`/
`GravityFtCovenantFlat` name + exact-indent strings; leave the BTC-payment
block + contract name untouched so fuse_anywallet runs cleanly. Rename last,
after any-wallet. (Here we keep the FT-style name so fuse_anywallet's
`GravityFtCovenantFlat` rename anchor still fires, then a final rename to
`GravityNftCovenant*` is applied by the build script after any-wallet.)

NFT has NO epilogue and NO OP_STATESEPARATOR: the funded UTXO is the compiled
script verbatim (the singleton is in the prologue, not appended).
"""

import re
import sys

src = sys.stdin.read()

# --- Delta 1: constructor params (flat path) ---
src = re.sub(r"^\s*bytes20 takerRadiantPkh,\n", "", src, flags=re.MULTILINE)
src = re.sub(r"^\s*bytes20 makerPkh,\n", "", src, flags=re.MULTILINE)
src = src.replace(
    "    int totalPhotonsInOutput\n) {",
    "    bytes32 expectedTakerNftHash,\n"
    "    bytes32 expectedMakerNftHash,\n"
    "    int nftCarrierValue,\n"
    "    bytes36 REF\n) {",
)

# --- Delta 2: shared preamble (NFT hardening) before `return {` ---
preamble = (
    "\n"
    "    // --- NFT hardening (runs on both branches). The singleton is HELD in\n"
    "    // the covenant via pushInputRefSingleton(REF). refOutputCount==1 is the\n"
    "    // SOLE guard against burning/cloning the NFT (consensus permits a burn).\n"
    "    bytes36 ref = pushInputRefSingleton(REF);\n"
    "    require(tx.outputs.length == 1);\n"
    "    require(tx.outputs.refOutputCount(ref) == 1);\n"
    "    require(tx.outputs[0].value == nftCarrierValue);\n"
)
assert "\n    return {" in src, "could not find `return {` insertion point"
src = src.replace("\n    return {", preamble + "\n    return {", 1)

# --- Delta 3: finalize route -> hash-compare to taker NFT ---
src = src.replace(
    "            // --- Route to Taker ---\n"
    "            bytes25 takerLock = new LockingBytecodeP2PKH(takerRadiantPkh);\n"
    "            require(tx.outputs[0].lockingBytecode == takerLock);\n"
    "            require(tx.outputs[0].value >= totalPhotonsInOutput);",
    "            // --- Route to Taker NFT (exact 63-B NFT script via hash-compare) ---\n"
    "            require(hash256(tx.outputs[0].lockingBytecode) == expectedTakerNftHash);",
)

# --- Delta 4: forfeit route -> hash-compare to maker NFT ---
src = src.replace(
    "            require(tx.time >= claimDeadline);\n"
    "            bytes25 makerLock = new LockingBytecodeP2PKH(makerPkh);\n"
    "            require(tx.outputs[0].lockingBytecode == makerLock);\n"
    "            require(tx.outputs[0].value >= totalPhotonsInOutput);",
    "            require(tx.time >= claimDeadline);\n"
    "            require(hash256(tx.outputs[0].lockingBytecode) == expectedMakerNftHash);",
)

# Contract NOT renamed here (transform-order contract) — leave MakerCovenantFlat
# so fuse_anywallet.py's anchors fire. The build script renames last.

# Sanity
assert "takerRadiantPkh" not in src, "takerRadiantPkh leaked"
assert "totalPhotonsInOutput" not in src, "totalPhotonsInOutput leaked"
assert "LockingBytecodeP2PKH" not in src, "P2PKH route not fully replaced"
assert "pushInputRefSingleton(REF)" in src
assert "expectedTakerNftHash" in src and "expectedMakerNftHash" in src
assert "refValueSum" not in src, "NFT must NOT have an amount/refValueSum check"

sys.stdout.write(src)
