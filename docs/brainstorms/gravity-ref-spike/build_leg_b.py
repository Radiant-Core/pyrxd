#!/usr/bin/env python3
"""Phase-2 Leg B: spend the covenant-prologue FT UTXO via the `settle` path ->
standard taker FT output. Exercises the covenant spend logic (sig check, the 3
hardening constraints, hash-compare) AND the FT epilogue conservation.

The prologue-FT UTXO is synthetic (the Leg-A output that WOULD exist if Leg A
were broadcast) — Leg B is a testmempoolaccept dry-run against it.

settle scriptSig (cashc convention, selector on top): <sig> <pubkey> <selector>
where settle = function index 0 -> selector OP_0 (empty push).

Outputs: [0] standard taker FT (76a914<taker_pkh>88ac bd d0 <ref> dec0..),
value = FT amount, carries the ref. Exactly one output (clamp).
A separate plain-RXD input pays the fee; but the covenant requires
outputs.length == 1, so the fee must be consumed entirely (no change output).
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

TAKER_WIF = sys.argv[1]              # taker signs the settle
PROLOGUE_FT_SPK_HEX = sys.argv[2]    # the covenant-prologue FT script (the UTXO being spent)
PROLOGUE_FT_TXID = sys.argv[3]       # synthetic source txid (Leg-A txid)
PROLOGUE_FT_VOUT = int(sys.argv[4])
FT_AMOUNT = int(sys.argv[5])
TAKER_FT_SPK_HEX = sys.argv[6]       # standard taker FT output script (output[0])
FEE_WIF = sys.argv[7]                # pays the fee (plain P2PKH)
FEE_TXID = sys.argv[8]
FEE_VOUT = int(sys.argv[9])
FEE_AMT = int(sys.argv[10])
FEE_SPK_HEX = sys.argv[11]

taker = PrivateKey(TAKER_WIF)
taker_pub = taker.public_key().serialize()
fee_key = PrivateKey(FEE_WIF)
fee_pub = fee_key.public_key().serialize()

prologue_ft_spk = bytes.fromhex(PROLOGUE_FT_SPK_HEX)


def _settle_unlock(tx, idx):
    """settle: <sig> <pubkey> <OP_0 selector>. Selector OP_0 = empty push."""
    inp = tx.inputs[idx]
    sig = taker.sign(tx.preimage(idx))
    return Script(
        encode_pushdata(sig + inp.sighash.to_bytes(1, "little"))
        + encode_pushdata(taker_pub)
        + b"\x00"  # OP_0 selector (settle = index 0)
    )


def _fee_unlock(tx, idx):
    inp = tx.inputs[idx]
    sig = fee_key.sign(tx.preimage(idx))
    return Script(encode_pushdata(sig + inp.sighash.to_bytes(1, "little")) + encode_pushdata(fee_pub))


# --- covenant-prologue FT input (the UTXO being settled) ---
src = Transaction(tx_inputs=[], tx_outputs=[
    TransactionOutput(Script(prologue_ft_spk), FT_AMOUNT)])
src.txid = lambda: PROLOGUE_FT_TXID  # type: ignore
cov_in = TransactionInput(source_transaction=src, source_txid=PROLOGUE_FT_TXID,
                          source_output_index=PROLOGUE_FT_VOUT,
                          unlocking_script_template=to_unlock_script_template(_settle_unlock, lambda: 150))
cov_in.satoshis = FT_AMOUNT
cov_in.locking_script = Script(prologue_ft_spk)

# --- fee input (plain P2PKH) ---
_fee_outs = [TransactionOutput(Script(b"\x00"), 0) for _ in range(FEE_VOUT)]
_fee_outs.append(TransactionOutput(Script(bytes.fromhex(FEE_SPK_HEX)), FEE_AMT))
fee_src = Transaction(tx_inputs=[], tx_outputs=_fee_outs)
fee_src.txid = lambda: FEE_TXID  # type: ignore
fee_in = TransactionInput(source_transaction=fee_src, source_txid=FEE_TXID,
                          source_output_index=FEE_VOUT,
                          unlocking_script_template=to_unlock_script_template(_fee_unlock, lambda: 110))
fee_in.satoshis = FEE_AMT
fee_in.locking_script = Script(bytes.fromhex(FEE_SPK_HEX))

# --- single output: standard taker FT (clamp requires outputs.length == 1) ---
# The fee is the difference (FT_AMOUNT + FEE_AMT) - FT_AMOUNT = FEE_AMT, all to miner.
tx = Transaction(
    tx_inputs=[cov_in, fee_in],
    tx_outputs=[TransactionOutput(Script(bytes.fromhex(TAKER_FT_SPK_HEX)), FT_AMOUNT)],
)
tx.sign()
raw = tx.serialize().hex()
print(json.dumps({"leg_b_hex": raw, "leg_b_txid": tx.txid(),
                  "fee_paid": FEE_AMT, "size_bytes": len(raw) // 2}))
