#!/usr/bin/env python3
"""Move a test NFT off a weak (low-entropy) key onto a properly-random rescue
key. Standard NFT transfer: spend the 63-byte NFT UTXO (owner P2PKH auth) + a
plain-RXD fee input -> new 63-byte NFT script at the rescue pkh + RXD change.
A plain NFT transfer has NO outputs.length==1 constraint, so change is allowed.

Outputs: [0] rescue NFT (carries the singleton), [1] RXD change to fee key.
"""
import json
import sys

from pyrxd.glyph.script import build_nft_locking_script
from pyrxd.glyph.types import GlyphRef
from pyrxd.keys import PrivateKey
from pyrxd.security.types import Hex20
from pyrxd.script.script import Script
from pyrxd.script.type import encode_pushdata, to_unlock_script_template
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_input import TransactionInput
from pyrxd.transaction.transaction_output import TransactionOutput

OWNER_WIF = sys.argv[1]       # weak key currently holding the NFT
RESCUE_PKH = sys.argv[2]      # destination pkh (strong key)
NFT_TXID = sys.argv[3]
NFT_VOUT = int(sys.argv[4])
NFT_SCRIPT_HEX = sys.argv[5]  # current 63-byte NFT script
NFT_VALUE = int(sys.argv[6])
REF_TXID = sys.argv[7]
REF_VOUT = int(sys.argv[8])
FEE_WIF = sys.argv[9]
FEE_TXID = sys.argv[10]
FEE_VOUT = int(sys.argv[11])
FEE_AMT = int(sys.argv[12])
FEE_SPK_HEX = sys.argv[13]

owner = PrivateKey(OWNER_WIF)
owner_pub = owner.public_key().serialize()
fee_key = PrivateKey(FEE_WIF)
fee_pub = fee_key.public_key().serialize()
fee_pkh = bytes(Hex20(fee_key.public_key().hash160()))

ref = GlyphRef(txid=REF_TXID, vout=REF_VOUT)
rescue_nft = build_nft_locking_script(Hex20(bytes.fromhex(RESCUE_PKH)), ref)


def _owner_unlock(tx, idx):
    inp = tx.inputs[idx]
    sig = owner.sign(tx.preimage(idx))
    return Script(encode_pushdata(sig + inp.sighash.to_bytes(1, "little")) + encode_pushdata(owner_pub))


def _fee_unlock(tx, idx):
    inp = tx.inputs[idx]
    sig = fee_key.sign(tx.preimage(idx))
    return Script(encode_pushdata(sig + inp.sighash.to_bytes(1, "little")) + encode_pushdata(fee_pub))


nft_src = Transaction(tx_inputs=[], tx_outputs=[TransactionOutput(Script(bytes.fromhex(NFT_SCRIPT_HEX)), NFT_VALUE)])
nft_src.txid = lambda: NFT_TXID  # type: ignore
nft_in = TransactionInput(source_transaction=nft_src, source_txid=NFT_TXID, source_output_index=NFT_VOUT,
                          unlocking_script_template=to_unlock_script_template(_owner_unlock, lambda: 110))
nft_in.satoshis = NFT_VALUE
nft_in.locking_script = Script(bytes.fromhex(NFT_SCRIPT_HEX))

_fee_outs = [TransactionOutput(Script(b"\x00"), 0) for _ in range(FEE_VOUT)]
_fee_outs.append(TransactionOutput(Script(bytes.fromhex(FEE_SPK_HEX)), FEE_AMT))
fee_src = Transaction(tx_inputs=[], tx_outputs=_fee_outs)
fee_src.txid = lambda: FEE_TXID  # type: ignore
fee_in = TransactionInput(source_transaction=fee_src, source_txid=FEE_TXID, source_output_index=FEE_VOUT,
                          unlocking_script_template=to_unlock_script_template(_fee_unlock, lambda: 110))
fee_in.satoshis = FEE_AMT
fee_in.locking_script = Script(bytes.fromhex(FEE_SPK_HEX))

FEE = 5_000_000  # ~411-byte tx at >10k photons/byte (Radiant min relay)
change_val = (NFT_VALUE + FEE_AMT) - NFT_VALUE - FEE
assert change_val > 546, f"change too small: {change_val}"
change_spk = b"\x76\xa9\x14" + fee_pkh + b"\x88\xac"

tx = Transaction(
    tx_inputs=[nft_in, fee_in],
    tx_outputs=[
        TransactionOutput(Script(rescue_nft), NFT_VALUE),
        TransactionOutput(Script(change_spk), change_val),
    ],
)
tx.sign()
raw = tx.serialize().hex()
print(json.dumps({"hex": raw, "txid": tx.txid(), "rescue_nft": rescue_nft.hex(),
                  "change_val": change_val, "size": len(raw) // 2}))
