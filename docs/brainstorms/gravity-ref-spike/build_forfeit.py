#!/usr/bin/env python3
"""Phase-4 forfeit proof: spend the fused-covenant FT UTXO via the `forfeit`
path -> standard MAKER FT output (after the CLTV deadline). No SPV proof.

forfeit = function index 1 -> selector OP_1. scriptSig: <makerSig> <makerPk> OP_1.
The covenant: require(tx.time >= claimDeadline); require(hash256(output[0]) ==
expectedMakerFtHash); plus the shared FT hardening (outputs.length==1, single
ref, refValueSum==amount). nLockTime must be in [claimDeadline, MTP] and input
sequence < 0xffffffff so OP_CHECKLOCKTIMEVERIFY is enforced.
"""
import json
import sys

from pyrxd.keys import PrivateKey
from pyrxd.script.script import Script
from pyrxd.script.type import encode_pushdata, to_unlock_script_template
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_input import TransactionInput
from pyrxd.transaction.transaction_output import TransactionOutput

MAKER_WIF = sys.argv[1]
FUSED_SPK_HEX = sys.argv[2]
FUSED_TXID = sys.argv[3]
FUSED_VOUT = int(sys.argv[4])
FT_AMOUNT = int(sys.argv[5])
MAKER_FT_SPK_HEX = sys.argv[6]
FEE_WIF = sys.argv[7]
FEE_TXID = sys.argv[8]
FEE_VOUT = int(sys.argv[9])
FEE_AMT = int(sys.argv[10])
FEE_SPK_HEX = sys.argv[11]
NLOCKTIME = int(sys.argv[12])

maker = PrivateKey(MAKER_WIF)
maker_pub = maker.public_key().serialize()
fee_key = PrivateKey(FEE_WIF)
fee_pub = fee_key.public_key().serialize()
fused_spk = bytes.fromhex(FUSED_SPK_HEX)


def _forfeit_unlock(tx, idx):
    # forfeit() takes NO params and does NO sig check — it is gated by CLTV
    # alone (anyone may broadcast after the deadline; the FT goes to the
    # maker's FT address regardless). Bare covenant => scriptSig is just the
    # OP_1 selector (no redeem script to push). Matches production
    # build_forfeit_tx (scriptSig = OP_1 + redeem); here the covenant IS the
    # scriptPubKey so there's no redeem push.
    return Script(b"\x51")  # OP_1 selector (forfeit)


def _fee_unlock(tx, idx):
    inp = tx.inputs[idx]
    sig = fee_key.sign(tx.preimage(idx))
    return Script(encode_pushdata(sig + inp.sighash.to_bytes(1, "little")) + encode_pushdata(fee_pub))


src = Transaction(tx_inputs=[], tx_outputs=[TransactionOutput(Script(fused_spk), FT_AMOUNT)])
src.txid = lambda: FUSED_TXID  # type: ignore
cov_in = TransactionInput(source_transaction=src, source_txid=FUSED_TXID, source_output_index=FUSED_VOUT,
                          unlocking_script_template=to_unlock_script_template(_forfeit_unlock, lambda: 150))
cov_in.satoshis = FT_AMOUNT
cov_in.locking_script = Script(fused_spk)
cov_in.sequence = 0xFFFFFFFE  # < max so nLockTime/CLTV is enforced

_fee_outs = [TransactionOutput(Script(b"\x00"), 0) for _ in range(FEE_VOUT)]
_fee_outs.append(TransactionOutput(Script(bytes.fromhex(FEE_SPK_HEX)), FEE_AMT))
fee_src = Transaction(tx_inputs=[], tx_outputs=_fee_outs)
fee_src.txid = lambda: FEE_TXID  # type: ignore
fee_in = TransactionInput(source_transaction=fee_src, source_txid=FEE_TXID, source_output_index=FEE_VOUT,
                          unlocking_script_template=to_unlock_script_template(_fee_unlock, lambda: 110))
fee_in.satoshis = FEE_AMT
fee_in.locking_script = Script(bytes.fromhex(FEE_SPK_HEX))
fee_in.sequence = 0xFFFFFFFE

tx = Transaction(
    tx_inputs=[cov_in, fee_in],
    tx_outputs=[TransactionOutput(Script(bytes.fromhex(MAKER_FT_SPK_HEX)), FT_AMOUNT)],
    locktime=NLOCKTIME,
)
tx.sign()
raw = tx.serialize().hex()
print(json.dumps({"hex": raw, "txid": tx.txid(), "nlocktime": NLOCKTIME, "size": len(raw) // 2}))
