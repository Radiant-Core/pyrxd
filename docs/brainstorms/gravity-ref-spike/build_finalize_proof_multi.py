#!/usr/bin/env python3
"""Phase-4 any-wallet proof: build a synthetic PoW-valid SPV proof whose BTC
payment tx is MULTI-INPUT + change-FIRST (the shape the single-input covenant
rejected). Proves the any-wallet covenant's finalize accepts it on-chain.

Tx: 2 native-segwit inputs; outputs = [P2TR change, P2WPKH payment, P2PKH change]
(payment in the MIDDLE). Header chain anchor 0x99*32, nBits 0x1d7fffff.
"""
import hashlib, json, struct, sys

sys.path.insert(0, "src")
from pyrxd.security.errors import SpvVerificationError  # noqa: E402
from pyrxd.spv import verify_header_pow  # noqa: E402

BTC_RECEIVE_HASH = bytes.fromhex(sys.argv[1])
BTC_SATOSHIS = int(sys.argv[2])
assert len(BTC_RECEIVE_HASH) == 20

VERSION = b"\x00\x00\x00\x20"
ANCHOR = b"\x99" * 32
NBITS = b"\xff\xff\x7f\x1d"
TIME = b"\x00\x00\x00\x00"


def h256(b): return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def _inp(txid_b, vout):
    return txid_b + struct.pack("<I", vout) + b"\x00" + b"\xff\xff\xff\xff"  # empty scriptSig (native segwit)


def _out(sats, spk):
    return struct.pack("<Q", sats) + bytes([len(spk)]) + spk


# Multi-input, change-first, payment in the middle.
p2wpkh = b"\x00\x14" + BTC_RECEIVE_HASH                  # payment (22B)
p2tr = b"\x51\x20" + b"\x11" * 32                        # change (34B)
p2pkh = b"\x76\xa9\x14" + b"\x44" * 20 + b"\x88\xac"     # change (25B)
raw_tx = (
    VERSION
    + b"\x02" + _inp(b"\xaa" * 32, 0) + _inp(b"\xbb" * 32, 1)
    + b"\x03" + _out(99999, p2tr) + _out(BTC_SATOSHIS, p2wpkh) + _out(55555, p2pkh)
    + b"\x00\x00\x00\x00"
)
assert len(raw_tx) > 64

txid_le = h256(raw_tx)
sibling_le = b"\xab" * 32
merkle_root_le = h256(sibling_le + txid_le)  # dir=0x01 (sibling left)
branch = b"\x01" + sibling_le + (b"\x02" + b"\x00" * 32) * 11  # depth 12


def grind(prev, mr):
    base = VERSION + prev + mr + TIME + NBITS
    for nonce in range(1 << 30):
        hdr = base + nonce.to_bytes(4, "little")
        h = h256(hdr)
        if h[29] == 0 and h[30] == 0 and h[31] == 0:
            try:
                verify_header_pow(hdr)
                return hdr
            except SpvVerificationError:
                continue
    raise RuntimeError("grind failed")


headers = []
prev = ANCHOR
for i in range(6):
    mr = merkle_root_le if i == 0 else h256(bytes([i]) * 32)
    hdr = grind(prev, mr)
    headers.append(hdr)
    prev = h256(hdr)
    print(f"  mined header {i+1}/6", file=sys.stderr)

print(json.dumps({
    "btc_chain_anchor": ANCHOR.hex(), "expected_nbits": NBITS.hex(),
    "btc_receive_hash": BTC_RECEIVE_HASH.hex(), "btc_satoshis": BTC_SATOSHIS,
    "headers": [h.hex() for h in headers], "branch_hex": branch.hex(),
    "raw_tx_hex": raw_tx.hex(), "merkle_root_le": merkle_root_le.hex(),
    "n_inputs": 2, "n_outputs": 3, "payment_output_index": 1,
}))
