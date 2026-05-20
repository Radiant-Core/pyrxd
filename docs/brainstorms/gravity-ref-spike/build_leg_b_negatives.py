#!/usr/bin/env python3
"""Phase-2 negative-case matrix for the covenant `settle` path. Each builds a
tx that VIOLATES one covenant constraint and is expected to be REJECTED by
testmempoolaccept on the real node. Prints one JSON line per case with the
constructed hex; the caller runs testmempoolaccept on each and asserts rejection.

Cases:
  extra_output    : two outputs (violates outputs.length == 1 clamp)
  wrong_taker     : output[0] is an FT to a DIFFERENT pkh (hash-compare fails)
  short_amount    : output[0] FT value < AMOUNT (refValueSum / OP_OUTPUTVALUE)
  cancel_attempt  : selector != 0/1 (no third branch) — and a maker-only
                    spend with selector that tries a non-existent cancel path
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

CASE = sys.argv[1]
TAKER_WIF = sys.argv[2]
PROLOGUE_FT_SPK_HEX = sys.argv[3]
PROLOGUE_FT_TXID = sys.argv[4]
PROLOGUE_FT_VOUT = int(sys.argv[5])
FT_AMOUNT = int(sys.argv[6])
TAKER_FT_SPK_HEX = sys.argv[7]
FEE_WIF = sys.argv[8]
FEE_TXID = sys.argv[9]
FEE_VOUT = int(sys.argv[10])
FEE_AMT = int(sys.argv[11])
FEE_SPK_HEX = sys.argv[12]
REF_WIRE = sys.argv[13]

taker = PrivateKey(TAKER_WIF)
taker_pub = taker.public_key().serialize()
fee_key = PrivateKey(FEE_WIF)
fee_pub = fee_key.public_key().serialize()
prologue_ft_spk = bytes.fromhex(PROLOGUE_FT_SPK_HEX)
fee_pkh = bytes(Hex20(fee_key.public_key().hash160()))


def _settle_unlock(tx, idx):
    inp = tx.inputs[idx]
    sig = taker.sign(tx.preimage(idx))
    return Script(encode_pushdata(sig + inp.sighash.to_bytes(1, "little"))
                  + encode_pushdata(taker_pub) + b"\x00")


def _settle_unlock_selector2(tx, idx):
    """cancel_attempt: push selector OP_2 (no such branch -> covenant rejects)."""
    inp = tx.inputs[idx]
    sig = taker.sign(tx.preimage(idx))
    return Script(encode_pushdata(sig + inp.sighash.to_bytes(1, "little"))
                  + encode_pushdata(taker_pub) + b"\x52")  # OP_2


def _fee_unlock(tx, idx):
    inp = tx.inputs[idx]
    sig = fee_key.sign(tx.preimage(idx))
    return Script(encode_pushdata(sig + inp.sighash.to_bytes(1, "little")) + encode_pushdata(fee_pub))


unlock = _settle_unlock_selector2 if CASE == "cancel_attempt" else _settle_unlock

src = Transaction(tx_inputs=[], tx_outputs=[TransactionOutput(Script(prologue_ft_spk), FT_AMOUNT)])
src.txid = lambda: PROLOGUE_FT_TXID  # type: ignore
cov_in = TransactionInput(source_transaction=src, source_txid=PROLOGUE_FT_TXID,
                          source_output_index=PROLOGUE_FT_VOUT,
                          unlocking_script_template=to_unlock_script_template(unlock, lambda: 150))
cov_in.satoshis = FT_AMOUNT
cov_in.locking_script = Script(prologue_ft_spk)

_fee_outs = [TransactionOutput(Script(b"\x00"), 0) for _ in range(FEE_VOUT)]
_fee_outs.append(TransactionOutput(Script(bytes.fromhex(FEE_SPK_HEX)), FEE_AMT))
fee_src = Transaction(tx_inputs=[], tx_outputs=_fee_outs)
fee_src.txid = lambda: FEE_TXID  # type: ignore
fee_in = TransactionInput(source_transaction=fee_src, source_txid=FEE_TXID,
                          source_output_index=FEE_VOUT,
                          unlocking_script_template=to_unlock_script_template(_fee_unlock, lambda: 110))
fee_in.satoshis = FEE_AMT
fee_in.locking_script = Script(bytes.fromhex(FEE_SPK_HEX))

taker_ft = bytes.fromhex(TAKER_FT_SPK_HEX)
# A "wrong taker" FT: same shape, attacker's pkh (fee_pkh stands in for attacker).
wrong_ft = b"\x76\xa9\x14" + fee_pkh + b"\x88\xac\xbd\xd0" + bytes.fromhex(REF_WIRE) + bytes.fromhex("dec0e9aa76e378e4a269e69d")

if CASE == "extra_output":
    outs = [TransactionOutput(Script(taker_ft), FT_AMOUNT),
            TransactionOutput(Script(b"\x76\xa9\x14" + fee_pkh + b"\x88\xac"), FEE_AMT - 8_000_000)]
elif CASE == "wrong_taker":
    outs = [TransactionOutput(Script(wrong_ft), FT_AMOUNT)]
elif CASE == "short_amount":
    # output FT value below AMOUNT; the rest would have to go somewhere, but
    # with one output the tx just has a smaller carrier value (fee absorbs rest).
    outs = [TransactionOutput(Script(taker_ft), FT_AMOUNT - 1)]
elif CASE == "cancel_attempt":
    outs = [TransactionOutput(Script(taker_ft), FT_AMOUNT)]
else:
    raise SystemExit(f"unknown case {CASE}")

tx = Transaction(tx_inputs=[cov_in, fee_in], tx_outputs=outs)
tx.sign()
print(json.dumps({"case": CASE, "hex": tx.serialize().hex(), "txid": tx.txid()}))
