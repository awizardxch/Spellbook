"""S-09: a plain EVM/Solana transfer's `asset` must name the native coin.

The EVM and Solana transfer executors send the native coin and never read
`asset`. Policy is keyed by (chain, asset), and DEX intents key policy on
token addresses, so a token-shaped label on a plain transfer would be
judged under the token's limits while native coin leaves the wallet. The
daemon refuses such labels at request time and again at execution.
"""
import pytest

from spellbook import evm
from spellbook import solana as solana_mod
from spellbook.daemon import Daemon
from spellbook.ledger import Ledger
from spellbook.policy import Policy

EVM_CHAIN = "evm-11155111"
TOKEN = "0x" + "11" * 20
DEST = "0x" + "22" * 20


def _bare_daemon(tmp_path, policy):
    d = Daemon.__new__(Daemon)
    d.config_dir = str(tmp_path)
    d.cfg = {}
    d.policy = policy
    d.ledger = Ledger(str(tmp_path / "ledger.jsonl"))
    d.queue = {}
    d.next_qid = 1
    d.queue_path = str(tmp_path / "queue.json")
    d.velocity = []
    d.velocity_path = str(tmp_path / "velocity.jsonl")
    d._save_queue = lambda: None
    d.evm_cfg = {}
    d.solana_cfg = {}
    return d


def test_token_label_on_evm_transfer_is_refused_before_policy(tmp_path,
                                                             monkeypatch):
    assert EVM_CHAIN in evm.CHAINS
    # The owner set a token-denominated auto-approve level (as DEX intents
    # invite); 100 tokens at 18 decimals.
    d = _bare_daemon(tmp_path, Policy(
        auto_approve_below={(EVM_CHAIN, TOKEN): 101 * 10 ** 18}))
    sent = []
    monkeypatch.setattr(d, "_execute_spend",
                        lambda p: sent.append(p) or {"submitted": True,
                                                     "tx_hash": "0xt"})
    out = d.rt_request_spend({"chain": EVM_CHAIN, "destination": DEST,
                              "asset": TOKEN, "amount_wei": 100 * 10 ** 18,
                              "purpose": "t"}, "m")
    assert out["ok"] is False and "native" in out["error"], out
    assert sent == [] and d.queue == {}
    # The same amount labeled as what is actually sent is judged under the
    # native key, where no auto-approve level covers it: it queues.
    out = d.rt_request_spend({"chain": EVM_CHAIN, "destination": DEST,
                              "amount_wei": 100 * 10 ** 18,
                              "purpose": "t"}, "m")
    assert out["ok"] is True and out["decision"] == "queued", out
    assert sent == []


def test_execution_refuses_a_queued_token_labeled_evm_transfer(tmp_path):
    """An item queued before the request-time check existed (or edited on
    disk) must still not send native wei under a token label."""
    d = _bare_daemon(tmp_path, Policy())
    with pytest.raises(evm.EvmError, match="native"):
        d._execute_spend({"chain": EVM_CHAIN, "destination": DEST,
                          "asset": TOKEN, "amount_wei": 1})


def test_solana_transfer_label_must_be_sol(tmp_path):
    chain = "solana-devnet"
    assert chain in solana_mod.NETWORKS
    d = _bare_daemon(tmp_path, Policy(
        auto_approve_below={(chain, "USDC"): 10 ** 12}))
    d._active_solana_chain = lambda: chain
    out = d.rt_request_spend({"chain": chain,
                              "destination": "So1ana" + "1" * 38,
                              "asset": "USDC", "amount_lamports": 5,
                              "purpose": "t"}, "m")
    assert out["ok"] is False and "SOL" in out["error"], out
    with pytest.raises(solana_mod.SolanaError, match="SOL"):
        d._execute_spend({"chain": chain, "destination": "x",
                          "asset": "USDC", "amount_lamports": 5})
