"""Type definitions for the dMint subpackage.

Pure data types consumed by ≥2 sibling submodules, plus the
``V2UnvalidatedWarning`` warning class and shared module-level byte
constants. Depends on nothing within the subpackage; siblings import
from here, not the reverse.

Symbols (15):
    V2UnvalidatedWarning,
    MAX_SHA256D_TARGET, MAX_V2_TARGET_256,
    DmintAlgo, DaaMode,
    _PART_B1, _PART_B2, _PART_B4,
    DmintDeployParams, DmintCborPayload, DmintMintResult,
    DmintV1ContractInitialState
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Any

from pyrxd.security.errors import ValidationError

from ..types import GlyphRef  # ..types resolves to pyrxd.glyph.types

# ---------------------------------------------------------------------------
# V2 quarantine marker
# ---------------------------------------------------------------------------
#
# V2 dMint is implemented per spec but **has never been validated against
# on-chain bytes** — no V2 contract exists on Radiant mainnet as of pyrxd
# 0.5.1. Every protocol-level claim in the V2 path is byte-derived from
# the V1 covenant (where the two share bytecode, e.g. ``_PART_C``) or
# from the V2 design doc; nothing is cross-validated against live
# transactions. This is the same anti-pattern that produced the M1
# mint-shape bug (docs/solutions/logic-errors/dmint-v1-mint-shape-mismatch.md)
# and the V2 reward-shape bug caught by the 0.5.0 red-team audit. The
# quarantine warning below is the smallest reversible signal we can put
# on every V2 entry point to make the "this path has never run on chain"
# status visible at runtime.


class V2UnvalidatedWarning(UserWarning):
    """Retained warning category for V2 dMint code paths.

    HISTORY: V2 dMint was once quarantined behind this warning because it had
    never been exercised against live consensus. That is no longer true — the
    canonical-Photonic V2 redesign is byte-matched to upstream and consensus-
    validated on radiant-core v3.1.1 regtest AND Radiant mainnet (3.1.2): the
    first V2 dMint deploy + PoW mint confirmed on mainnet (deploy
    ``95335028…bb16fb09``, mint ``1239f64a…e0cd6c67``; #219). The per-call
    warning is therefore no longer emitted.

    The class is kept (not deleted) so any downstream ``warnings.simplefilter(…,
    V2UnvalidatedWarning)`` filters remain importable. V2 is still **pre-external-
    audit** — that caveat lives in the README / threat-model, the same level as
    V1, not in a per-call warning.
    """


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Maximum SHA256d target (64-bit; first 4 bytes implicitly zero).
# Valid: hash[0..4] == 0 AND hash[4..12] < MAX_SHA256D_TARGET.
MAX_SHA256D_TARGET = 0x7FFFFFFFFFFFFFFF

# Maximum V2 256-bit target for blake3 / k12.
MAX_V2_TARGET_256 = (1 << 256) - 1

# EPOCH DAA: allowed max-adjustment factors and their log2 (shift count). Restricted
# to powers of 2 so the boundary clamp uses bit-shifts (N× OP_2MUL / OP_2DIV).
EPOCH_MAX_ADJUSTMENT_LOG2_VALUES = (1, 2, 3, 4)  # → 2× / 4× / 8× / 16×
# EPOCH target ceiling: target > 2^48 risks overflow in `target × clampedDelta`
# (clampedDelta ≤ targetTime × 2^N). Enforced at deploy when daa_mode == EPOCH.
EPOCH_MAX_SAFE_TARGET = 1 << 48

# SCHEDULE DAA: maximum number of (height, target) entries in a baked schedule.
SCHEDULE_MAX_ENTRIES = 10

# ---------------------------------------------------------------------------
# ASERT-v2 fractional fixed-point DAA constants
# ---------------------------------------------------------------------------
#
# pyrxd's on-chain "ASERT" through 0.9 was an INTEGER power-of-2 stepper
# (drift = trunc(excess / halfLife) clamped [-4,+4]; target *= 2^drift). The
# 2026-06-19 DAA review found three structural defects: a dead zone (|excess| <
# halfLife → drift truncates to 0 → no move), a one-sided ratchet (raising
# difficulty needs excess <= targetTime - halfLife < 0, impossible whenever
# halfLife >= targetTime), and >=2x lurches off a single nLockTime sample.
# ASERT-v2 replaces it with a FRACTIONAL fixed-point step in the same int64
# domain the script VM enforces, reusing LWMA's divide-first + MAX/4 cap (so the
# same difficulty floor of 4 applies). Canonical byte-for-byte reference:
# Photonic-Wallet packages/lib/src/dmintDaaV2.ts (computeAsertV2Target) and
# script.ts (buildAsertDaaBytecode). The two formats coexist on-chain: contracts
# deployed before the upgrade keep the legacy bytecode and must keep mining under
# the legacy formula, so the miner distinguishes them by codescript signature.
ASERT_V2_RADIX = 1 << 16  # 65536 — fixed-point scale (drift is carried as drift × 2^16)
ASERT_V2_DRIFT_CLAMP = ASERT_V2_RADIX >> 2  # 16384 — ±RADIX/4 ⇒ target moves at most ±25%/mint
ASERT_V2_MAX_TARGET_DIV4 = MAX_SHA256D_TARGET >> 2  # 0x1FFF…F — headroom + difficulty floor 4 (as LWMA)
# Canonical default ASERT halfLife (seconds) when a deploy omits it: ≈4× the
# default 60s targetBlockTime. MUST equal Photonic script.ts DEFAULT_ASERT_HALFLIFE.
DEFAULT_ASERT_HALFLIFE = 240


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class DmintAlgo(IntEnum):
    SHA256D = 0
    BLAKE3 = 1
    K12 = 2


class DaaMode(IntEnum):
    FIXED = 0
    EPOCH = 1
    ASERT = 2
    LWMA = 3
    SCHEDULE = 4


# ---------------------------------------------------------------------------
# V2 bytecode constants (Part B — shared by builders and chain)
# ---------------------------------------------------------------------------

# OP_STATESEPARATOR — used in builders (V1+V2 contract assembler) and chain
# (V2 state parser). Placed here (types.py) rather than chain.py so that
# builders.py can use it without a builders → chain import that would
# violate the one-way dependency graph.
_OP_STATESEPARATOR = b"\xbd"

# Part B.1: PoW hash extraction (shared by all modes)
_PART_B1 = bytes.fromhex("bc01147f77587f040000000088817600a269")

# Part B.2: target comparison (V2 preserves target for DAA)
_PART_B2 = bytes.fromhex("51797ca269")

# Part B.4: TOALTSTACK newTarget + 4×OP_DROP (lastTime, targetTime, daaMode, algoId).
# The pre-redesign shape was ``7575757575`` (5×OP_DROP), which discarded the
# DAA-computed newTarget so difficulty never advanced on-chain. ``6b`` (TOALTSTACK)
# preserves newTarget on the alt stack for Part C to write into the next state.
_PART_B4 = bytes.fromhex("6b75757575")

# NOTE: Part C is no longer a fixed constant. In the redesign it is
# deploy-parameterized (embeds the immutable state slots so it can rebuild the
# next-state script and let ASERT/LWMA advance difficulty), so it is built per
# contract by ``builders._build_part_c(middle_literal)`` rather than stored here.


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DmintDeployParams:
    """Parameters for deploying a V2 dMint contract."""

    contract_ref: GlyphRef  # singleton ref (will become contractRef in state)
    token_ref: GlyphRef  # normal ref (will become tokenRef in state)
    max_height: int  # maximum number of mints
    reward: int  # photons per mint
    difficulty: int  # initial difficulty → determines initial target
    algo: DmintAlgo = DmintAlgo.SHA256D
    daa_mode: DaaMode = DaaMode.FIXED
    target_time: int = 60  # seconds between mints (for DAA modes)
    half_life: int = DEFAULT_ASERT_HALFLIFE  # ASERT half-life in seconds (canonical default ≈4× target_time)
    height: int = 0  # current mint height (0 at deploy)
    last_time: int = 0  # timestamp of last mint (0 at deploy)
    epoch_length: int = 2016  # EPOCH: retarget every N blocks
    max_adjustment_log2: int = 2  # EPOCH: max adjustment 2^N per epoch (1..4 → 2×..16×)
    schedule: tuple[tuple[int, int], ...] = ()  # SCHEDULE: ascending (height, target) entries

    def __post_init__(self) -> None:
        if self.max_height < 1:
            raise ValidationError("max_height must be >= 1")
        if self.reward < 1:
            raise ValidationError("reward must be >= 1 photon")
        if self.difficulty < 1:
            raise ValidationError("difficulty must be >= 1")
        if self.target_time < 1:
            raise ValidationError("target_time must be >= 1 second")
        if self.half_life < 1:
            raise ValidationError("half_life must be >= 1 second")
        if self.height < 0:
            raise ValidationError("height must be >= 0")
        if self.last_time < 0:
            raise ValidationError("last_time must be >= 0")
        if self.daa_mode == DaaMode.EPOCH:
            if self.epoch_length < 1:
                raise ValidationError("epoch_length must be >= 1 for EPOCH")
            if self.max_adjustment_log2 not in EPOCH_MAX_ADJUSTMENT_LOG2_VALUES:
                raise ValidationError(
                    f"max_adjustment_log2 must be one of {EPOCH_MAX_ADJUSTMENT_LOG2_VALUES} for EPOCH "
                    f"(got {self.max_adjustment_log2})"
                )
            # target × clampedDelta must not overflow int64 → cap target at 2^48.
            if self.initial_target > EPOCH_MAX_SAFE_TARGET:
                raise ValidationError(
                    f"EPOCH requires initial target <= 2^48 (use difficulty >= "
                    f"{MAX_SHA256D_TARGET // EPOCH_MAX_SAFE_TARGET + 1}); got target {self.initial_target} "
                    "— larger targets risk OP_MUL overflow in the on-chain retarget"
                )
        if self.daa_mode == DaaMode.SCHEDULE:
            if not self.schedule:
                raise ValidationError("SCHEDULE requires a non-empty schedule (use FIXED for no schedule)")
            if len(self.schedule) > SCHEDULE_MAX_ENTRIES:
                raise ValidationError(
                    f"SCHEDULE allows at most {SCHEDULE_MAX_ENTRIES} entries, got {len(self.schedule)}"
                )
            prev_h = -1
            for i, (h, t) in enumerate(self.schedule):
                if h < 0:
                    raise ValidationError(f"SCHEDULE entry {i}: height must be >= 0, got {h}")
                if h <= prev_h:
                    raise ValidationError(f"SCHEDULE entries must be strictly ascending by height (entry {i})")
                if not 1 <= t <= MAX_SHA256D_TARGET:
                    raise ValidationError(f"SCHEDULE entry {i}: target must be in [1, MAX_SHA256D_TARGET], got {t}")
                prev_h = h

    @property
    def initial_target(self) -> int:
        """Compute initial target from difficulty using the SHA256d formula."""
        if self.algo == DmintAlgo.SHA256D:
            return MAX_SHA256D_TARGET // self.difficulty
        return MAX_V2_TARGET_256 // self.difficulty


@dataclass(frozen=True)
class DmintCborPayload:
    """The ``dmint`` object embedded in Glyph V2 token metadata CBOR.

    Indexers read this to discover dMint contracts and display mining
    parameters in wallets/explorers without parsing the contract script.

    Field names mirror Photonic Wallet ``DmintPayload`` type in types.ts. This is
    the indexer-facing **display** metadata; it carries CBOR-native values, which
    for two EPOCH/SCHEDULE fields differ from how ``DmintDeployParams`` stores them
    — convert at the call site:

    * ``max_adjustment`` is the adjustment **multiplier** (2/4/8/16), i.e.
      ``2 ** DmintDeployParams.max_adjustment_log2``.
    * ``schedule`` entries are ``(height, difficulty)``, where
      ``difficulty = target_to_difficulty(target, algo)`` for each deploy
      ``(height, target)`` pair.
    """

    algo: DmintAlgo  # 0=sha256d, 1=blake3, 2=k12
    num_contracts: int  # number of parallel mining contract UTXOs
    max_height: int  # total mints allowed
    reward: int  # photons per mint
    premine: int  # photons pre-minted to deployer (0 if none)
    diff: int  # initial difficulty (1 = easiest)
    daa_mode: DaaMode = DaaMode.FIXED
    target_block_time: int = 60  # seconds between mints (ignored for FIXED)
    half_life: int = 0  # ASERT half-life seconds (0 = N/A)
    window_size: int = 0  # LWMA window size (0 = N/A)
    asymptote: int = 0  # ASERT asymptote (0 = N/A; optional, mirrors Photonic)
    epoch_length: int = 0  # EPOCH retarget interval in blocks (0 = N/A)
    max_adjustment: int = 0  # EPOCH max-adjustment MULTIPLIER 2/4/8/16 (0 = N/A; = 2**max_adjustment_log2)
    schedule: tuple[tuple[int, int], ...] = ()  # SCHEDULE: ascending (height, difficulty) entries

    def __post_init__(self) -> None:
        if self.num_contracts < 1:
            raise ValidationError("num_contracts must be >= 1")
        if self.max_height < 1:
            raise ValidationError("max_height must be >= 1")
        if self.reward < 0:
            raise ValidationError("reward must be >= 0")
        if self.premine < 0:
            raise ValidationError("premine must be >= 0")
        if self.diff < 1:
            raise ValidationError("diff must be >= 1")
        if self.asymptote < 0:
            raise ValidationError("asymptote must be >= 0")
        if self.epoch_length < 0:
            raise ValidationError("epoch_length must be >= 0")
        if self.max_adjustment < 0:
            raise ValidationError("max_adjustment must be >= 0")

    def to_cbor_dict(self) -> dict:
        """Encode to the dict that becomes the ``dmint`` CBOR value."""
        d: dict = {
            "algo": int(self.algo),
            "numContracts": self.num_contracts,
            "maxHeight": self.max_height,
            "reward": self.reward,
            "premine": self.premine,
            "diff": self.diff,
        }
        if self.daa_mode != DaaMode.FIXED:
            daa: dict = {
                "mode": int(self.daa_mode),
                "targetBlockTime": self.target_block_time,
            }
            if self.half_life:
                daa["halfLife"] = self.half_life
            if self.asymptote:
                daa["asymptote"] = self.asymptote
            if self.window_size:
                daa["windowSize"] = self.window_size
            if self.epoch_length:
                daa["epochLength"] = self.epoch_length
            if self.max_adjustment:
                daa["maxAdjustment"] = self.max_adjustment
            if self.schedule:
                daa["schedule"] = [{"height": h, "difficulty": diff} for h, diff in self.schedule]
            d["daa"] = daa
        return d

    @classmethod
    def from_cbor_dict(cls, d: dict) -> DmintCborPayload:
        """Parse the ``dmint`` CBOR value from an on-chain payload."""
        try:
            algo = DmintAlgo(int(d["algo"]))
        except (KeyError, ValueError) as e:
            raise ValidationError("dmint.algo missing or invalid") from e
        try:
            daa_mode = DaaMode.FIXED
            target_block_time = 60
            half_life = 0
            window_size = 0
            asymptote = 0
            epoch_length = 0
            max_adjustment = 0
            schedule: tuple[tuple[int, int], ...] = ()
            if "daa" in d:
                daa = d["daa"]
                daa_mode = DaaMode(int(daa.get("mode", 0)))
                target_block_time = int(daa.get("targetBlockTime", 60))
                half_life = int(daa.get("halfLife", 0))
                window_size = int(daa.get("windowSize", 0))
                asymptote = int(daa.get("asymptote", 0))
                epoch_length = int(daa.get("epochLength", 0))
                max_adjustment = int(daa.get("maxAdjustment", 0))
                sched_raw = daa.get("schedule")
                if sched_raw:
                    schedule = tuple((int(e["height"]), int(e["difficulty"])) for e in sched_raw)
            return cls(
                algo=algo,
                num_contracts=int(d.get("numContracts", 1)),
                max_height=int(d["maxHeight"]),
                reward=int(d["reward"]),
                premine=int(d.get("premine", 0)),
                diff=int(d["diff"]),
                daa_mode=daa_mode,
                target_block_time=target_block_time,
                half_life=half_life,
                window_size=window_size,
                asymptote=asymptote,
                epoch_length=epoch_length,
                max_adjustment=max_adjustment,
                schedule=schedule,
            )
        except KeyError as e:
            raise ValidationError(f"dmint CBOR missing required field: {e}") from e


@dataclass
class DmintMintResult:
    """Output of :func:`build_dmint_mint_tx`.

    :param tx:                 Unsigned transaction (caller must sign).
    :param updated_state:      New :class:`DmintState` written into the
                               contract output (height incremented, target
                               updated if DAA is active).
    :param contract_script:    New contract output script (state + separator + code).
    :param reward_script:      P2PKH locking script of the miner reward output.
    :param fee:                Transaction fee in photons.

    .. note::
       The transaction returned here is **unsigned** — it uses raw script bytes
       for the contract input's unlocking script (nonce + preimage halves) built
       by :func:`build_mint_scriptsig`.  The contract script is a covenant, not
       a P2PKH, so standard :class:`Transaction.sign()` is not appropriate.
       The caller must either set the unlocking script directly or use a custom
       signing path.  See docstring of :func:`build_dmint_mint_tx` for details.
    """

    tx: Any
    updated_state: Any  # DmintState — forward reference; resolved at runtime
    contract_script: bytes
    reward_script: bytes
    fee: int


@dataclass(frozen=True)
class DmintV1ContractInitialState:
    """Just-deployed state of a V1 dMint contract template.

    Carries exactly the parameters needed to reconstruct the initial
    (height=0) contract codescript for *every* contract of a given
    deploy. Used by :func:`find_dmint_contract_utxos`'s fast path,
    where the caller already knows the deploy params.

    :param num_contracts: Count of parallel contracts the deploy created
        (1..255 for V1; mainnet GLYPH used 32).
    :param reward_sats: Photons emitted per successful mint (must fit in
        3 bytes — V1 protocol constant).
    :param max_height: Maximum mints per contract (3-byte ceiling).
    :param target: 8-byte SHA256d PoW target.
    :param algo: PoW algorithm. Defaults to ``DmintAlgo.SHA256D``,
        which is the only algorithm seen on V1 mainnet.
    """

    num_contracts: int
    reward_sats: int
    max_height: int
    target: int
    algo: DmintAlgo = DmintAlgo.SHA256D
