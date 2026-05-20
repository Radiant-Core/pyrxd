#!/usr/bin/env python3
"""Spike step 3: substitute the FT-release covenant params and compute its
P2SH address + redeem script. REF = the minted FT's ref (txid:vout wire form)."""
import json
import sys

from pyrxd.glyph.types import GlyphRef
from pyrxd.security.types import Hex20
from pyrxd.keys import PrivateKey

ARTIFACT = "docs/brainstorms/gravity-ref-spike/GravityFtReleaseSpike.artifact.json"

FT_REF_TXID = sys.argv[1]
FT_REF_VOUT = int(sys.argv[2])
AMOUNT = int(sys.argv[3])
TAKER_WIF = sys.argv[4]
MAKER_WIF = sys.argv[5]
DEADLINE = int(sys.argv[6])

ref = GlyphRef(txid=FT_REF_TXID, vout=FT_REF_VOUT)
ref_wire = ref.to_bytes()  # 36 bytes
taker_pkh = bytes(Hex20(PrivateKey(TAKER_WIF).public_key().hash160()))
maker_pkh = bytes(Hex20(PrivateKey(MAKER_WIF).public_key().hash160()))

art = json.load(open(ARTIFACT))
hex_template = art["hex"]

# The compiler emits placeholders as <NAME> in the hex. Substitute each with
# its minimal/fixed-width push-less raw bytes (constructor params are pushed by
# the spending scriptSig as constructor args, but in this artifact they are
# baked as template placeholders to be filled into the redeem script).
# int params (AMOUNT, DEADLINE) use Radiant scriptnum (minimal LE) encoding.
def scriptnum(n: int) -> bytes:
    if n == 0: return b""
    neg = n < 0; n = abs(n); out = bytearray()
    while n: out.append(n & 0xFF); n >>= 8
    if out[-1] & 0x80: out.append(0x80 if neg else 0x00)
    elif neg: out[-1] |= 0x80
    return bytes(out)

subs = {
    "REF": ref_wire.hex(),
    "AMOUNT": scriptnum(AMOUNT).hex(),
    "TAKER_PKH": taker_pkh.hex(),
    "MAKER_PKH": maker_pkh.hex(),
    "DEADLINE": scriptnum(DEADLINE).hex(),
}

redeem_hex = hex_template
for name, val in subs.items():
    redeem_hex = redeem_hex.replace(f"<{name}>", val)

assert "<" not in redeem_hex, f"unfilled placeholder remains: {redeem_hex}"
covenant_spk = bytes.fromhex(redeem_hex)

# BARE deployment: the covenant scriptPubKey IS the substituted covenant
# bytecode. It leads with OP_PUSHINPUTREF <REF>, so the funded UTXO exposes
# the ref opcode (conservation satisfied). NO P2SH wrap — that would hide the
# ref behind a914<hash>87 and burn it.
assert covenant_spk[:1] == b"\xd0", "covenant must lead with OP_PUSHINPUTREF (0xd0)"

print(json.dumps({
    "covenant_spk_hex": covenant_spk.hex(),
    "covenant_spk_len": len(covenant_spk),
    "ref_wire_hex": ref_wire.hex(),
    "taker_pkh": taker_pkh.hex(),
    "maker_pkh": maker_pkh.hex(),
    "amount": AMOUNT,
    "deadline": DEADLINE,
}))
