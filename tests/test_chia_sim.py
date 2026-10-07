"""Simulator verification of Chialisp-audit finding S1 (2026-10-07).

Runs the daemon's own signer against chia-blockchain's spend simulator
(``chia._tests.util.spend_sim``: real mempool manager, coin store, BLS
``AGG_SIG_ME`` checks). Adapted from the audit probe
``sim_spellbook_curry.py``; the probe's three S1 failures must now pass:

  1. the daemon's puzzle hash for a key == chia-blockchain's
     ``puzzle_for_synthetic_public_key(...).get_tree_hash()``;
  2. a coin at that address is spent by the daemon's own builder AND a
     chia-blockchain-built spend of a sibling coin at the same address
     succeeds (one address, two independent signers);
  3. a coin at the pre-fix LEGACY address is still spendable by the
     daemon through its legacy path (sweep), while a stock-wallet reveal
     cannot spend it (WRONG_PUZZLE_HASH) — which is why the legacy path
     has to exist.

Skipped ONLY when chia-blockchain is not importable; the skip reason
names that so it is visible in the test summary (``-rs``).
"""
import asyncio
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from spellbook import chia_sign as cs  # noqa: E402

try:
    from chia._tests.util.spend_sim import sim_and_client
    from chia.types.blockchain_format.program import Program
    from chia.types.coin_spend import make_spend
    from chia.types.mempool_inclusion_status import MempoolInclusionStatus as MIS
    from chia.wallet.puzzles.p2_delegated_puzzle_or_hidden_puzzle import (
        DEFAULT_HIDDEN_PUZZLE_HASH,
        calculate_synthetic_secret_key,
        puzzle_for_synthetic_public_key,
        solution_for_conditions,
    )
    from chia_rs import AugSchemeMPL, G1Element, PrivateKey, SpendBundle
    from chia_rs.sized_bytes import bytes32
except ImportError as e:  # pragma: no cover — environment without chia
    pytest.skip(
        "chia-blockchain not importable "
        f"({e.__class__.__name__}: {e}) — S1 SIMULATOR VERIFICATION NOT RUN",
        allow_module_level=True,
    )

OUT_PH = bytes32(b"\x42" * 32)


async def _largest_unspent(client, ph: bytes32):
    recs = await client.get_coin_records_by_puzzle_hash(
        ph, include_spent_coins=False)
    assert recs, f"no unspent coins at {ph.hex()[:16]}…"
    return max((r.coin for r in recs), key=lambda c: c.amount)


async def _push(client, bundle):
    st, err = await client.push_tx(bundle)
    return st, (err.name if err else None)


async def _scenario() -> dict:
    out = {}
    async with sim_and_client() as (sim, client):
        add = sim.defaults.AGG_SIG_ME_ADDITIONAL_DATA
        nets = [k for k, v in cs.GENESIS_CHALLENGE.items() if v == add]
        assert nets, "simulator genesis challenge matches no spellbook network"
        net = nets[0]
        out["network"] = net

        # The audit probe's key material (a throwaway test key, never a
        # wallet): BLS key_gen of 32 bytes of 0x07, wallet index 0.
        master = bytes(AugSchemeMPL.key_gen(b"\x07" * 32))
        wsk = cs.wallet_sk(master, 0)
        spk = cs.synthetic_pk(cs.pk_bytes(wsk))
        chia_ssk = calculate_synthetic_secret_key(
            PrivateKey.from_bytes(wsk), DEFAULT_HIDDEN_PUZZLE_HASH)
        out["synthetic_pk_matches_chia"] = bytes(chia_ssk.get_g1()) == spk

        daemon_ph = cs.puzzle_hash_for_synthetic_pk(spk)
        std_puzzle = puzzle_for_synthetic_public_key(G1Element.from_bytes(spk))
        std_ph = std_puzzle.get_tree_hash()
        legacy_ph = cs.legacy_puzzle_hash_for_synthetic_pk(spk)
        out["daemon_ph"] = daemon_ph.hex()
        out["standard_ph"] = std_ph.hex()
        out["legacy_ph"] = legacy_ph.hex()
        out["same_address"] = daemon_ph == bytes(std_ph)
        out["same_reveal"] = cs.standard_puzzle_reveal(spk) == bytes(std_puzzle)

        # Fund: two blocks to the standard address (sibling coins for the
        # two signers), one block to the legacy address.
        await sim.farm_block(std_ph)
        await sim.farm_block(std_ph)
        await sim.farm_block(bytes32(legacy_ph))

        # (2a) the daemon's own builder spends a coin at the standard address
        coin_a = await _largest_unspent(client, std_ph)
        spend = cs.build_standard_spend(
            master, 0, (coin_a.parent_coin_info, coin_a.puzzle_hash, coin_a.amount),
            [(OUT_PH, coin_a.amount)], net)
        out["daemon_spend_is_legacy"] = spend["legacy"]
        st, err = await _push(client, SpendBundle.from_bytes(cs.build_spend_bundle([spend])))
        out["daemon_spends_standard_coin"] = (st.name, err)
        if st == MIS.SUCCESS:
            await sim.farm_block()
        rec = await client.get_coin_record_by_name(coin_a.name())
        out["daemon_spent_coin_confirmed"] = bool(rec and rec.spent)

        # (2b) a chia-blockchain-built spend of a SIBLING coin at the same address
        coin_b = await _largest_unspent(client, std_ph)
        assert coin_b.name() != coin_a.name()
        conds = [[51, OUT_PH, coin_b.amount]]
        sol = solution_for_conditions(Program.to(conds))
        msg = Program.to((1, conds)).get_tree_hash() + coin_b.name() + add
        sig = AugSchemeMPL.sign(chia_ssk, msg)
        st, err = await _push(client, SpendBundle([make_spend(coin_b, std_puzzle, sol)], sig))
        out["chia_spends_sibling_coin"] = (st.name, err)
        if st == MIS.SUCCESS:
            await sim.farm_block()

        # (3a) a stock-wallet reveal cannot spend the LEGACY coin …
        legacy_coin = await _largest_unspent(client, bytes32(legacy_ph))
        conds = [[51, OUT_PH, legacy_coin.amount]]
        sol = solution_for_conditions(Program.to(conds))
        msg = Program.to((1, conds)).get_tree_hash() + legacy_coin.name() + add
        st, err = await _push(client, SpendBundle(
            [make_spend(legacy_coin, std_puzzle, sol)], AugSchemeMPL.sign(chia_ssk, msg)))
        out["chia_reveal_on_legacy_coin"] = (st.name, err)

        # (3b) … but the daemon sweeps it through its legacy path, to the
        # standard address.
        spend = cs.build_standard_spend(
            master, 0,
            (legacy_coin.parent_coin_info, legacy_coin.puzzle_hash, legacy_coin.amount),
            [(daemon_ph, legacy_coin.amount)], net)
        out["legacy_spend_is_legacy"] = spend["legacy"]
        st, err = await _push(client, SpendBundle.from_bytes(cs.build_spend_bundle([spend])))
        out["daemon_sweeps_legacy_coin"] = (st.name, err)
        if st == MIS.SUCCESS:
            await sim.farm_block()
        rec = await client.get_coin_record_by_name(legacy_coin.name())
        out["legacy_coin_spent_confirmed"] = bool(rec and rec.spent)
        swept = await client.get_coin_records_by_puzzle_hash(std_ph, include_spent_coins=False)
        out["swept_to_standard"] = any(r.coin.amount == legacy_coin.amount
                                       and r.coin.parent_coin_info == legacy_coin.name()
                                       for r in swept)
    return out


@pytest.fixture(scope="module")
def sim_results():
    results = asyncio.run(_scenario())
    # The probe's report lines, for `pytest -s`.
    print()
    print(f"simulator genesis challenge matches spellbook network {results['network']!r}")
    print(f"synthetic pk equal to chia-blockchain's: {results['synthetic_pk_matches_chia']}")
    print(f"spellbook puzzle hash : {results['daemon_ph']}")
    print(f"standard  puzzle hash : {results['standard_ph']}")
    print(f"legacy    puzzle hash : {results['legacy_ph']}")
    print(f"same address: {results['same_address']}")
    print(f"[S1] daemon reveal spends standard-address coin: {results['daemon_spends_standard_coin']}")
    print(f"[S1] chia-blockchain reveal spends sibling coin at the same address: {results['chia_spends_sibling_coin']}")
    print(f"[S1] chia-blockchain reveal on a LEGACY coin: {results['chia_reveal_on_legacy_coin']}")
    print(f"[S1] daemon legacy path sweeps the LEGACY coin to the standard address: {results['daemon_sweeps_legacy_coin']}")
    return results


def test_daemon_address_equals_chia_blockchain_puzzle_hash(sim_results):
    assert sim_results["synthetic_pk_matches_chia"]
    assert sim_results["same_address"], (
        f"spellbook {sim_results['daemon_ph']} != chia {sim_results['standard_ph']}")
    assert sim_results["same_reveal"]
    assert sim_results["legacy_ph"] != sim_results["standard_ph"]


def test_daemon_builder_spends_coin_at_standard_address(sim_results):
    assert sim_results["daemon_spend_is_legacy"] is False
    assert sim_results["daemon_spends_standard_coin"] == ("SUCCESS", None)
    assert sim_results["daemon_spent_coin_confirmed"]


def test_chia_built_spend_of_sibling_coin_succeeds(sim_results):
    assert sim_results["chia_spends_sibling_coin"] == ("SUCCESS", None)


def test_legacy_coin_sweepable_only_through_daemon_legacy_path(sim_results):
    assert sim_results["chia_reveal_on_legacy_coin"] == ("FAILED", "WRONG_PUZZLE_HASH")
    assert sim_results["legacy_spend_is_legacy"] is True
    assert sim_results["daemon_sweeps_legacy_coin"] == ("SUCCESS", None)
    assert sim_results["legacy_coin_spent_confirmed"]
    assert sim_results["swept_to_standard"]
