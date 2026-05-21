#!/usr/bin/env python3
"""Reference validation of the any-wallet BTC-tx parser's offset arithmetic
(mirrors the RadiantScript walk in AnyWalletParse.rxd). Builds a 2-input,
change-first, mixed-output-type tx and confirms the walk finds the P2WPKH
payment at output[1] — the shape the single-input covenant rejected.
Run: python3 validate_anywallet_parse.py
"""
import struct


def build_multi_input_tx(btc_hash: bytes, pay_sats: int) -> bytes:
    p2wpkh = b"\x00\x14" + btc_hash
    payment = struct.pack("<Q", pay_sats) + bytes([len(p2wpkh)]) + p2wpkh
    p2tr = b"\x51\x20" + b"\x11" * 32  # change is a different output type
    change = struct.pack("<Q", 99999) + bytes([len(p2tr)]) + p2tr

    def inp(txid_b, vout):
        return txid_b + struct.pack("<I", vout) + b"\x00" + b"\xff\xff\xff\xff"

    return (
        struct.pack("<I", 2)
        + b"\x02"
        + inp(b"\xaa" * 32, 0)
        + inp(b"\xbb" * 32, 1)
        + b"\x02"
        + change   # output[0] = change (payment is NOT first)
        + payment  # output[1] = payment
        + struct.pack("<I", 0)
    )


def parse_find_payment(rawtx: bytes, btc_hash: bytes, min_sats: int) -> bool:
    """The covenant's walk: skip version + N native-segwit inputs, scan outputs."""
    i = lambda b: int.from_bytes(b, "little")
    pos = 4
    n_in = rawtx[pos]
    pos += 1
    assert 1 <= n_in <= 8
    for _ in range(n_in):
        assert rawtx[pos + 36] == 0x00, "native segwit (empty scriptSig) only"
        pos += 41
    n_out = rawtx[pos]
    pos += 1
    found = False
    for _ in range(n_out):
        v = i(rawtx[pos : pos + 8])
        sl = rawtx[pos + 8]
        spk = rawtx[pos + 9 : pos + 9 + sl]
        if sl == 22 and spk[:2] == b"\x00\x14" and spk[2:] == btc_hash and v >= min_sats:
            found = True
        pos += 9 + sl
    return found


if __name__ == "__main__":
    h = bytes.fromhex("9995c9ac3bd932a75dca3229e3195c3544d5db36")
    tx = build_multi_input_tx(h, 10000)
    assert parse_find_payment(tx, h, 10000), "parser failed to find payment"
    # negative: wrong hash must NOT be found
    assert not parse_find_payment(tx, b"\x00" * 20, 10000), "false positive on wrong hash"
    # negative: amount too high must NOT be found
    assert not parse_find_payment(tx, h, 20000), "false positive on insufficient value"
    print("any-wallet parser offset arithmetic: PASS (2-input, change-first, mixed types)")
