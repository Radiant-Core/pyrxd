#!/usr/bin/env python3
"""Phase-2 Leg A harness: build the covenant-prologue FT output script
(mechanism 1a) — the funded UTXO is:

    <GravityFtPrologue compiled> bd d0 <genesis_ref> dec0e9aa76e378e4a269e69d

This is an FT-shaped UTXO whose spend is gated by the covenant prologue.
Because the codeScriptHash covers only the bytes from OP_STATESEPARATOR (bd)
onward (Radiant-Core script_execution_context.h:275-285), this output has the
SAME codeScriptHash as a standard-P2PKH-prologue FT for the same ref, so a
standard FT can be transferred into it and conservation holds.

Prints JSON: {prologue_ft_spk_hex, len, ref_wire_hex, sep_index, ref_count,
expected_taker_ft_hash, expected_maker_ft_hash}. Asserts the static invariants
(no bare bd in prologue, single separator at the epilogue, one distinct ref)
before emitting — the same checks that would catch a regression before broadcast.
"""
import hashlib
import json
import sys

from pyrxd.glyph.types import GlyphRef
from pyrxd.keys import PrivateKey
from pyrxd.security.types import Hex20

ARTIFACT = "docs/brainstorms/gravity-ref-spike/GravityFtPrologue.artifact.json"
FT_EPILOGUE = bytes.fromhex("dec0e9aa76e378e4a269e69d")  # 12-byte FT-CSH suffix

GENESIS_TXID = sys.argv[1]
GENESIS_VOUT = int(sys.argv[2])
AMOUNT = int(sys.argv[3])
TAKER_WIF = sys.argv[4]
MAKER_WIF = sys.argv[5]
DEADLINE = int(sys.argv[6])

ref = GlyphRef(txid=GENESIS_TXID, vout=GENESIS_VOUT)
ref_wire = ref.to_bytes()  # 36 bytes
taker_pkh = bytes(Hex20(PrivateKey(TAKER_WIF).public_key().hash160()))
maker_pkh = bytes(Hex20(PrivateKey(MAKER_WIF).public_key().hash160()))

hex_template = json.load(open(ARTIFACT))["hex"]


def scriptnum(n: int) -> bytes:
    if n == 0:
        return b""
    neg = n < 0
    n = abs(n)
    out = bytearray()
    while n:
        out.append(n & 0xFF)
        n >>= 8
    if out[-1] & 0x80:
        out.append(0x80 if neg else 0x00)
    elif neg:
        out[-1] |= 0x80
    return bytes(out)


def push(b: bytes) -> bytes:
    n = len(b)
    if n == 0:
        return b"\x00"
    if n <= 75:
        return bytes([n]) + b
    if n <= 255:
        return b"\x4c" + bytes([n]) + b
    raise ValueError(f"push too large: {n}")


def ft_locking_script(pkh: bytes) -> bytes:
    """Standard 75-byte FT holder script — mirror of build_ft_locking_script."""
    return b"\x76\xa9\x14" + pkh + b"\x88\xac\xbd\xd0" + ref_wire + FT_EPILOGUE


def hash256(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


expected_taker_ft_hash = hash256(ft_locking_script(taker_pkh))
expected_maker_ft_hash = hash256(ft_locking_script(maker_pkh))

# <REF> raw (OP_PUSHINPUTREF operand); all other params push-wrapped.
subs = {
    "REF": ref_wire.hex(),
    "AMOUNT": push(scriptnum(AMOUNT)).hex(),
    "EXPECTED_TAKER_FT_HASH": push(expected_taker_ft_hash).hex(),
    "MAKER_PKH": push(maker_pkh).hex(),
    "EXPECTED_MAKER_FT_HASH": push(expected_maker_ft_hash).hex(),
    "DEADLINE": push(scriptnum(DEADLINE)).hex(),
}
prologue_hex = hex_template
for name, val in subs.items():
    prologue_hex = prologue_hex.replace(f"<{name}>", val)
assert "<" not in prologue_hex, f"unfilled placeholder: {prologue_hex}"
prologue = bytes.fromhex(prologue_hex)

# Full covenant-prologue FT script = prologue + bd d0 <ref> dec0..
prologue_ft = prologue + b"\xbd\xd0" + ref_wire + FT_EPILOGUE


def _walk(spk: bytes):
    """Return (ref_opcode_positions_with_refs, opcode_position_bd_indices)."""
    REF_OPS = {0xD0, 0xD1, 0xD2, 0xD3, 0xD8}
    i = 0
    refs, bds = [], []
    while i < len(spk):
        op = spk[i]
        if op == 0xBD:
            bds.append(i)
        if op in REF_OPS:
            refs.append(spk[i + 1 : i + 37].hex())
            i += 37
            continue
        if 0x01 <= op <= 0x4B:
            i += 1 + op
            continue
        if op == 0x4C:
            i += 2 + spk[i + 1]
            continue
        if op == 0x4D:
            i += 3 + (spk[i + 1] | (spk[i + 2] << 8))
            continue
        if op == 0x4E:
            i += 5 + int.from_bytes(spk[i + 1 : i + 5], "little")
            continue
        i += 1
    return refs, bds

# Static invariants (regression guards before any broadcast):
_, prologue_bds = _walk(prologue)
assert not prologue_bds, f"prologue has bare OP_STATESEPARATOR at {prologue_bds}"
refs, full_bds = _walk(prologue_ft)
assert full_bds == [len(prologue)], f"separator boundary wrong: {full_bds} != [{len(prologue)}]"
distinct = set(refs)
assert distinct == {ref_wire.hex()}, f"unexpected refs: {distinct}"

print(
    json.dumps(
        {
            "prologue_ft_spk_hex": prologue_ft.hex(),
            "len": len(prologue_ft),
            "prologue_len": len(prologue),
            "ref_wire_hex": ref_wire.hex(),
            "sep_index": len(prologue),
            "ref_count_distinct": len(distinct),
            "expected_taker_ft_hash": expected_taker_ft_hash.hex(),
            "expected_maker_ft_hash": expected_maker_ft_hash.hex(),
            "taker_pkh": taker_pkh.hex(),
            "maker_pkh": maker_pkh.hex(),
            "amount": AMOUNT,
            "deadline": DEADLINE,
        }
    )
)
