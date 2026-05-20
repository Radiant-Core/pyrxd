#!/usr/bin/env python3
"""Phase-2 Leg A: transfer the standard test FT -> the covenant-prologue FT
output. Proves on a real node (via testmempoolaccept) that a covenant-prologue
FT output conserves against a standard FT input (same codeScriptHash).

Inputs:  [0] the standard FT UTXO (P2PKH-prologue), signed by the deploy key
         [1] a plain-RXD fee UTXO (deploy key)
Outputs: [0] covenant-prologue FT (value = FT amount = 100000; carries the ref)
         [1] plain-RXD change to the deploy key
"""
import json
import sys

from pyrxd.keys import PrivateKey
from pyrxd.security.types import Hex20
from pyrxd.script.script import Script
from pyrxd.script.type import encode_pushdata, to_unlock_script_template
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_input import TransactionInput
from pyrxd.transaction.transaction_output import TransactionOutput

DEPLOY_WIF = sys.argv[1]
PROLOGUE_FT_SPK_HEX = sys.argv[2]   # covenant-prologue FT output script
FT_TXID = sys.argv[3]               # standard FT UTXO being spent
FT_VOUT = int(sys.argv[4])
FT_SCRIPT_HEX = sys.argv[5]         # the 75-byte standard FT script on that UTXO
FT_AMOUNT = int(sys.argv[6])        # 100000
FEE_TXID = sys.argv[7]
FEE_VOUT = int(sys.argv[8])
FEE_AMT = int(sys.argv[9])
FEE_SPK_HEX = sys.argv[10]

key = PrivateKey(DEPLOY_WIF)
pubkey = key.public_key().serialize()
pkh = bytes(Hex20(key.public_key().hash160()))
prologue_ft_spk = bytes.fromhex(PROLOGUE_FT_SPK_HEX)


def _unlock(tx, idx):
    inp = tx.inputs[idx]
    sig = key.sign(tx.preimage(idx))
    return Script(encode_pushdata(sig + inp.sighash.to_bytes(1, "little")) + encode_pushdata(pubkey))


# --- FT input (standard P2PKH-prefixed FT) ---
ft_src = Transaction(tx_inputs=[], tx_outputs=[
    TransactionOutput(Script(bytes.fromhex(FT_SCRIPT_HEX)), FT_AMOUNT)])
ft_src.txid = lambda: FT_TXID  # type: ignore
ft_in = TransactionInput(source_transaction=ft_src, source_txid=FT_TXID,
                         source_output_index=FT_VOUT,
                         unlocking_script_template=to_unlock_script_template(_unlock, lambda: 110))
ft_in.satoshis = FT_AMOUNT
ft_in.locking_script = Script(bytes.fromhex(FT_SCRIPT_HEX))

# --- fee input (plain P2PKH) ---
_fee_outs = [TransactionOutput(Script(b"\x00"), 0) for _ in range(FEE_VOUT)]
_fee_outs.append(TransactionOutput(Script(bytes.fromhex(FEE_SPK_HEX)), FEE_AMT))
fee_src = Transaction(tx_inputs=[], tx_outputs=_fee_outs)
fee_src.txid = lambda: FEE_TXID  # type: ignore
fee_in = TransactionInput(source_transaction=fee_src, source_txid=FEE_TXID,
                          source_output_index=FEE_VOUT,
                          unlocking_script_template=to_unlock_script_template(_unlock, lambda: 110))
fee_in.satoshis = FEE_AMT
fee_in.locking_script = Script(bytes.fromhex(FEE_SPK_HEX))

# --- outputs: prologue-FT (FT_AMOUNT) + change ---
FEE = 8_000_000  # ~generous; ~14k/byte for a ~560B tx
change_val = FEE_AMT - FEE
assert change_val > 546, f"change too small: {change_val}"
change_spk = b"\x76\xa9\x14" + pkh + b"\x88\xac"

tx = Transaction(
    tx_inputs=[ft_in, fee_in],
    tx_outputs=[
        TransactionOutput(Script(prologue_ft_spk), FT_AMOUNT),
        TransactionOutput(Script(change_spk), change_val),
    ],
)
tx.sign()
raw = tx.serialize().hex()
print(json.dumps({"leg_a_hex": raw, "leg_a_txid": tx.txid(),
                  "prologue_ft_vout": 0, "prologue_ft_value": FT_AMOUNT,
                  "change_val": change_val, "size_bytes": len(raw) // 2}))
