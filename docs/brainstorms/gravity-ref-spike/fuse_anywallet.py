#!/usr/bin/env python3
"""Phase-4 any-wallet integration: transform the fused FT covenant
(GravityFtCovenant.rxd) so its BTC-payment verification accepts ANY
single-sig-segwit-input wallet tx (multi-input, change anywhere) instead of
the fixed single-input/fixed-offset shape. Reads the fused covenant on stdin,
writes the any-wallet covenant on stdout.

Two replacements (everything else verbatim — SPV header/Merkle, FT hardening,
hash-compare routes):
1. The fixed tx-layout block -> input-skip (per-input scriptSigLen varint,
   caps <=4) computing `pos` at the output-count, reading `nOut`.
2. The fixed-offset P2WPKH payment block -> output-scan (per-output scriptLen
   varint, caps <=4) setting `found`, then `require(found)`.

Safety: rawTx is Merkle-pinned (hash256(rawTx) leaf), so parsing it is
forgery-proof; the covenant computes every offset itself (no attacker offset
arg) — preserves audit-03-C2's intent. Caps are liveness limits.
"""
import sys

src = sys.stdin.read()

# --- Replacement 1: tx-layout block -> input-skip ---
OLD_LAYOUT_START = "            // --- Tx-structure constraint (forces known output offset) ---"
# the block runs through the outputCountByteVal != 0xff require.
old_layout_anchor_end = "            require(outputCountByteVal != 0xff);"
i0 = src.index(OLD_LAYOUT_START)
i1 = src.index(old_layout_anchor_end) + len(old_layout_anchor_end)
new_input_skip = """            // --- Any-wallet input skip (any-wallet design note 2026-05-20) ---
            // rawTx is Merkle-pinned (hash256(rawTx) leaf), so parsing it is
            // forgery-proof; we compute every offset ourselves (no attacker
            // offset arg). Caps: <=4 inputs / <=4 outputs (liveness, not safety).
            require(rawTx.length > 64);
            int nIn = int(rawTx.split(4)[1].split(1)[0]);
            require(nIn >= 1);
            require(nIn <= 4);
            int pos = 5;
            // Skip each input: 36 outpoint + scriptSigLen varint(1) + scriptSig + 4 seq.
            // Handles native-segwit/P2TR (scriptSig 0x00) and P2SH-P2WPKH (0x16..).
            int ssl1 = int(rawTx.split(pos + 36)[1].split(1)[0]);
            pos = pos + 36 + 1 + ssl1 + 4;
            if (nIn >= 2) { int ssl2 = int(rawTx.split(pos + 36)[1].split(1)[0]); pos = pos + 36 + 1 + ssl2 + 4; }
            if (nIn >= 3) { int ssl3 = int(rawTx.split(pos + 36)[1].split(1)[0]); pos = pos + 36 + 1 + ssl3 + 4; }
            if (nIn >= 4) { int ssl4 = int(rawTx.split(pos + 36)[1].split(1)[0]); pos = pos + 36 + 1 + ssl4 + 4; }
            // pos now -> output-count varint.
            int nOut = int(rawTx.split(pos)[1].split(1)[0]);
            require(nOut >= 1);
            require(nOut <= 4);
            pos = pos + 1;"""
src = src[:i0] + new_input_skip + src[i1:]

# --- Replacement 2: fixed-offset payment block -> output-scan ---
OLD_PAY = """            // --- BTC payment verification (P2WPKH) ---
            // P2WPKH: 31-byte output
            bytes output = rawTx.split(outputOffset)[1].split(31)[0];
            int value = int(output.split(8)[0]);
            require(value >= btcSatoshis);
            bytes scriptSection = output.split(8)[1];
            bytes prefix = scriptSection.split(3)[0];
            require(prefix == 0x160014);
            bytes hash = scriptSection.split(3)[1];
            require(hash == btcReceiveHash);"""
NEW_SCAN = """            // --- Any-wallet output scan: find a P2WPKH payment >= btcSatoshis ---
            // Each output: value(8) + scriptLen varint(1) + script(scriptLen).
            // Payment may sit at ANY output index (change anywhere).
            bool found = false;
            int v1 = int(rawTx.split(pos)[1].split(8)[0]);
            int sl1 = int(rawTx.split(pos + 8)[1].split(1)[0]);
            if (sl1 == 22) { if (rawTx.split(pos + 9)[1].split(2)[0] == 0x0014) { if (rawTx.split(pos + 11)[1].split(20)[0] == btcReceiveHash) { if (v1 >= btcSatoshis) { found = true; } } } }
            pos = pos + 9 + sl1;
            if (nOut >= 2) {
                int v2 = int(rawTx.split(pos)[1].split(8)[0]);
                int sl2 = int(rawTx.split(pos + 8)[1].split(1)[0]);
                if (sl2 == 22) { if (rawTx.split(pos + 9)[1].split(2)[0] == 0x0014) { if (rawTx.split(pos + 11)[1].split(20)[0] == btcReceiveHash) { if (v2 >= btcSatoshis) { found = true; } } } }
                pos = pos + 9 + sl2;
            }
            if (nOut >= 3) {
                int v3 = int(rawTx.split(pos)[1].split(8)[0]);
                int sl3 = int(rawTx.split(pos + 8)[1].split(1)[0]);
                if (sl3 == 22) { if (rawTx.split(pos + 9)[1].split(2)[0] == 0x0014) { if (rawTx.split(pos + 11)[1].split(20)[0] == btcReceiveHash) { if (v3 >= btcSatoshis) { found = true; } } } }
                pos = pos + 9 + sl3;
            }
            if (nOut >= 4) {
                int v4 = int(rawTx.split(pos)[1].split(8)[0]);
                int sl4 = int(rawTx.split(pos + 8)[1].split(1)[0]);
                if (sl4 == 22) { if (rawTx.split(pos + 9)[1].split(2)[0] == 0x0014) { if (rawTx.split(pos + 11)[1].split(20)[0] == btcReceiveHash) { if (v4 >= btcSatoshis) { found = true; } } } }
            }
            require(found);"""
assert OLD_PAY in src, "fixed-offset payment block not found verbatim"
src = src.replace(OLD_PAY, NEW_SCAN, 1)

# Rename contract so the artifact is distinct.
src = src.replace("contract GravityFtCovenantFlat", "contract GravityFtCovenantAnyWalletFlat")

# Sanity: outputOffset must be fully gone.
assert "outputOffset" not in src, "outputOffset leaked — replacement incomplete"
assert "found" in src and "nOut" in src

sys.stdout.write(src)
