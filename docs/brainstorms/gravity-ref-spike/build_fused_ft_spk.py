#!/usr/bin/env python3
"""Build the fused FT-covenant funding script (the FT-shaped UTXO whose spend
is gated by the full SPV + FT covenant):

    <GravityFtCovenant substituted> bd d0 <genesis_ref> dec0e9aa76e378e4a269e69d

Substitutes the fused-covenant constructor params (push-wrapped per the rxdc
ABI; REF raw after the leading d0), appends the FT epilogue, and re-runs the
two static guards (no bare bd before the epilogue separator; exactly one ref).
Prints JSON.
"""
import hashlib
import json
import sys

from pyrxd.glyph.script import count_input_refs
from pyrxd.glyph.types import GlyphRef
from pyrxd.keys import PrivateKey
from pyrxd.security.types import Hex20

ARTIFACT = "docs/brainstorms/gravity-ref-spike/GravityFtCovenant.artifact.json"
FT_EPILOGUE = bytes.fromhex("dec0e9aa76e378e4a269e69d")

GENESIS_TXID = sys.argv[1]
GENESIS_VOUT = int(sys.argv[2])
AMOUNT = int(sys.argv[3])
TAKER_WIF = sys.argv[4]
MAKER_WIF = sys.argv[5]
CLAIM_DEADLINE = int(sys.argv[6])
BTC_RECEIVE_HASH = sys.argv[7]      # 20-byte hex (p2wpkh hash) — per-offer derived in prod
BTC_SATOSHIS = int(sys.argv[8])
BTC_CHAIN_ANCHOR = sys.argv[9]      # 32-byte hex
EXPECTED_NBITS = sys.argv[10]       # 4-byte hex LE
EXPECTED_NBITS_NEXT = sys.argv[11]

ref = GlyphRef(txid=GENESIS_TXID, vout=GENESIS_VOUT)
ref_wire = ref.to_bytes()
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
    return b"\x4d" + n.to_bytes(2, "little") + b


def ft_script(pkh: bytes) -> bytes:
    return b"\x76\xa9\x14" + pkh + b"\x88\xac\xbd\xd0" + ref_wire + FT_EPILOGUE


def hash256(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


expected_taker_ft_hash = hash256(ft_script(taker_pkh))
expected_maker_ft_hash = hash256(ft_script(maker_pkh))

subs = {
    "REF": ref_wire.hex(),  # raw — follows the leading d0
    "btcReceiveHash": push(bytes.fromhex(BTC_RECEIVE_HASH)).hex(),
    "btcSatoshis": push(scriptnum(BTC_SATOSHIS)).hex(),
    "btcChainAnchor": push(bytes.fromhex(BTC_CHAIN_ANCHOR)).hex(),
    "expectedNBits": push(bytes.fromhex(EXPECTED_NBITS)).hex(),
    "expectedNBitsNext": push(bytes.fromhex(EXPECTED_NBITS_NEXT)).hex(),
    "claimDeadline": push(scriptnum(CLAIM_DEADLINE)).hex(),
    "amount": push(scriptnum(AMOUNT)).hex(),
    "expectedTakerFtHash": push(expected_taker_ft_hash).hex(),
    "expectedMakerFtHash": push(expected_maker_ft_hash).hex(),
}
spk_hex = hex_template
for name, val in subs.items():
    spk_hex = spk_hex.replace(f"<{name}>", val)
assert "<" not in spk_hex, f"unfilled placeholder: {spk_hex[spk_hex.index('<'):][:40]}"
prologue = bytes.fromhex(spk_hex)
fused_ft = prologue + b"\xbd\xd0" + ref_wire + FT_EPILOGUE


# Static guards (regression before broadcast).
def _opcode_bd_positions(spk: bytes):
    REF_OPS = {0xD0, 0xD1, 0xD2, 0xD3, 0xD8}
    i = 0
    bds = []
    while i < len(spk):
        op = spk[i]
        if op == 0xBD:
            bds.append(i)
        if op in REF_OPS:
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
    return bds


bds = _opcode_bd_positions(fused_ft)
assert bds == [len(prologue)], f"GUARD 1 FAIL: bd positions {bds} != [{len(prologue)}]"
refs = count_input_refs(fused_ft)
assert set(refs) == {ref_wire}, f"GUARD 2 FAIL: refs {refs}"

print(
    json.dumps(
        {
            "fused_ft_spk_hex": fused_ft.hex(),
            "len": len(fused_ft),
            "prologue_len": len(prologue),
            "ref_wire_hex": ref_wire.hex(),
            "expected_taker_ft_hash": expected_taker_ft_hash.hex(),
            "expected_maker_ft_hash": expected_maker_ft_hash.hex(),
            "taker_pkh": taker_pkh.hex(),
            "maker_pkh": maker_pkh.hex(),
            "amount": AMOUNT,
            "claim_deadline": CLAIM_DEADLINE,
        }
    )
)
