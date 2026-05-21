#!/usr/bin/env python3
"""Phase-4 finalize proof: build a synthetic-but-PoW-valid SPV proof of a
P2WPKH BTC payment, mine the 6-header chain the covenant requires, and emit
the params + scriptSig pieces. Synthetic chain (anchor 0x99*32, nbits
0x1d7fffff) is fine — the covenant runs the same PoW/Merkle/anchor checks
the Python verifier does, so a node accepts it iff we bake the matching
btcChainAnchor/expectedNBits into the covenant.

Layout the covenant expects (native segwit, --btc-type p2wpkh):
  rawTx = version(4) | 01 inputCount | 36B outpoint | 00 emptyScriptSig
        | 04B sequence | 01 outputCount | output[0] @ byte 47
  output[0] (31B) = value(8 LE) | 0x16 0x00 0x14 <20B btcReceiveHash>
Header: version(4) | prevHash(32) | merkleRoot(32) | time(4) | nBits(4) | nonce(4)

Prints JSON: {btc_chain_anchor, expected_nbits, btc_receive_hash, btc_satoshis,
headers (6 hex), branch_hex (1 real level + 11 sentinel), raw_tx_hex}.
"""
import hashlib
import json
import sys

# Use the real verifier so mined headers definitely pass verify_chain (the
# fast 3-zero-byte gate only approximates the 0x1d7fffff target).
sys.path.insert(0, "src")
from pyrxd.security.errors import SpvVerificationError  # noqa: E402
from pyrxd.spv import verify_header_pow  # noqa: E402

BTC_RECEIVE_HASH = bytes.fromhex(sys.argv[1])  # 20-byte p2wpkh hash
BTC_SATOSHIS = int(sys.argv[2])

assert len(BTC_RECEIVE_HASH) == 20

VERSION = b"\x00\x00\x00\x20"
ANCHOR = b"\x99" * 32          # h1.prevHash; covenant bakes btcChainAnchor = this
NBITS = b"\xff\xff\x7f\x1d"    # 0x1d7fffff — easy synthetic target
TIME = b"\x00\x00\x00\x00"


def h256(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


# --- payment tx (native segwit shape; output[0] at byte 47) ---
p2wpkh_script = b"\x00\x14" + BTC_RECEIVE_HASH       # OP_0 PUSH20 <hash> (22 bytes)
output0 = BTC_SATOSHIS.to_bytes(8, "little") + bytes([len(p2wpkh_script)]) + p2wpkh_script  # 8+1+22 = 31
raw_tx = (
    VERSION
    + b"\x01"                  # 1 input
    + b"\x00" * 32             # prev txid
    + b"\xff\xff\xff\xff"      # prev vout
    + b"\x00"                  # empty scriptSig (native segwit)
    + b"\xff\xff\xff\xff"      # sequence
    + b"\x01"                  # 1 output
    + output0
    + b"\x00\x00\x00\x00"      # locktime
)
assert len(raw_tx) > 64
output_offset = 47
assert raw_tx[output_offset : output_offset + 8] == BTC_SATOSHIS.to_bytes(8, "little"), "output not at byte 47"

txid_le = h256(raw_tx)

# --- Merkle: tx at position 1, single real sibling (coinbase-ish at pos 0) ---
sibling_le = b"\xab" * 32
merkle_root_le = h256(sibling_le + txid_le)  # current = hash256(sibling + tx) for dir=0x01 (sibling left)
# branch level 0: dir=0x01 (sibling on the left), sibling = sibling_le; then 11 sentinel levels.
branch = b"\x01" + sibling_le + (b"\x02" + b"\x00" * 32) * 11  # 33 + 11*33 = 396 bytes (depth 12)


def grind(prev: bytes, merkle_root: bytes) -> bytes:
    base = VERSION + prev + merkle_root + TIME + NBITS
    for nonce in range(1 << 30):
        header = base + nonce.to_bytes(4, "little")
        h = h256(header)
        if h[29] == 0 and h[30] == 0 and h[31] == 0:  # fast gate before the exact check
            try:
                verify_header_pow(header)  # exact 0x1d7fffff target comparison
                return header
            except SpvVerificationError:
                continue
    raise RuntimeError("grind failed")


# h1 carries the payment's merkle root and chains from the anchor.
# h2..h6 are filler (any merkle root) chaining h{i}.prev = hash256(h{i-1}).
headers = []
prev = ANCHOR
for i in range(6):
    mr = merkle_root_le if i == 0 else h256(bytes([i]) * 32)
    hdr = grind(prev, mr)
    headers.append(hdr)
    prev = h256(hdr)
    print(f"  mined header {i+1}/6", file=sys.stderr)

print(
    json.dumps(
        {
            "btc_chain_anchor": ANCHOR.hex(),
            "expected_nbits": NBITS.hex(),
            "btc_receive_hash": BTC_RECEIVE_HASH.hex(),
            "btc_satoshis": BTC_SATOSHIS,
            "headers": [h.hex() for h in headers],
            "branch_hex": branch.hex(),
            "raw_tx_hex": raw_tx.hex(),
            "merkle_root_le": merkle_root_le.hex(),
        }
    )
)
