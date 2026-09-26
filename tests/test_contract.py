"""Tests for the contract-interaction intents (SPEC §10 v3):
contract_deploy, contract_call, contract_call_view.

- spellbook.abi is cross-verified against eth-abi — a TEST-ONLY oracle
  (pip eth-abi); src/ never imports it.
- Daemon tests reuse the fake-Rpc pattern from test_daemon.py: no network.
"""
import json
import sys

import pytest

sys.path.insert(0, "tests")

from spellbook import abi, evm  # noqa: E402

# Test-only oracle: NEVER imported by src/.
from eth_abi import decode as eth_decode  # noqa: E402
from eth_abi import encode as eth_encode  # noqa: E402

A = "0x" + "11" * 20
B = "0x" + "22" * 20
H32 = "0x" + "33" * 32


def _oracle_vals(types, vals):
    """Convert our JSON-friendly values to eth_abi's expected forms."""
    out = []
    for t, v in zip(types, vals):
        base = t.rstrip("0123456789[]")
        if isinstance(v, (list, tuple)):
            out.append([_oracle_vals([base or t], [x])[0] for x in v])
        elif isinstance(v, str) and v.startswith("0x") and (
                base == "bytes" or (t.startswith("bytes") and t != "bytes")):
            out.append(bytes.fromhex(v[2:]))
        else:
            out.append(v)
    return out


# ------------------------------------------------------------ abi: encode

def test_encode_matches_eth_abi_oracle():
    cases = [
        (["address", "uint256"], [A, 12345]),
        (["bytes32", "uint256", "address"], [H32, 7200, B]),
        (["bool", "string", "bytes"], [True, "hello", "0xdeadbeef"]),
        (["address[]", "uint256[]"], [[A, B], [1, 2, 3]]),
        (["uint256[2][3]"], [[[1, 2], [3, 4], [5, 6]]]),
        (["bytes[]"], [["0x11", "0x2233"]]),
        (["int128"], [-42]),
        (["bytes4"], ["0xdeadbeef"]),
        (["uint256[][]"], [[[1, 2], [3]]]),
        (["string[2]"], [["a", "b"]]),
        (["uint8"], [255]),
        (["uint256[]", "string"], [[7, 8], "xyz"]),
        ([], []),
    ]
    for types, vals in cases:
        assert abi.encode_args(types, vals).hex() == \
            eth_encode(types, _oracle_vals(types, vals)).hex(), types


def test_encode_htlc_constructor_shape():
    """The exact 11-arg HTLCEscrow constructor shape from the Nightspire
    spec encodes byte-identical to the oracle."""
    types = ["address", "address", "bytes32", "uint256", "address",
             "uint256", "bytes32", "bytes32", "address", "address",
             "uint256"]
    vals = [A, B, H32, 999999, A, 5000, H32, H32, B, A, 888888]
    assert abi.encode_args(types, vals).hex() == \
        eth_encode(types, _oracle_vals(types, vals)).hex()


def test_encode_function_selector():
    cd = abi.encode_function_call(
        {"name": "transfer",
         "inputs": [{"name": "to", "type": "address"},
                    {"name": "value", "type": "uint256"}]},
        [A, 1])
    assert cd.startswith("0xa9059cbb")  # canonical ERC-20 transfer selector


def test_encode_constructor_appends_args():
    code = "0x60806040"
    out = abi.encode_constructor(
        code, {"inputs": [{"name": "x", "type": "uint256"}]}, [7])
    assert out == "0x60806040" + (7).to_bytes(32, "big").hex()


def test_encode_rejects():
    with pytest.raises(abi.AbiError):
        abi.encode_args(["(uint256,address)"], [(1, A)])  # tuples refused
    with pytest.raises(abi.AbiError):
        abi.encode_args(["uint256"], [True])  # bool is not a uint
    with pytest.raises(abi.AbiError):
        abi.encode_args(["uint8"], [256])  # out of range
    with pytest.raises(abi.AbiError):
        abi.encode_args(["address"], ["0x123"])  # malformed address
    with pytest.raises(abi.AbiError):
        abi.encode_args(["uint256", "uint256"], [1])  # arity mismatch
    with pytest.raises(abi.AbiError):
        abi.encode_args(["uint256[2]"], [[1]])  # static length mismatch
    with pytest.raises(abi.AbiError):
        abi.encode_args(["bytes2"], ["0x112233"])  # wrong length
    with pytest.raises(abi.AbiError):
        abi.encode_constructor("0x", None, [])  # empty bytecode
    with pytest.raises(abi.AbiError):
        abi.encode_constructor("0x" + "ff" * 49153, None, [])  # > EIP-3860
    with pytest.raises(abi.AbiError):
        abi.encode_function_call({"inputs": []}, [])  # no name
    with pytest.raises(abi.AbiError):
        abi.encode_args(["ufixed128x18"], [1])  # fixed-point refused


# ------------------------------------------------------------ abi: decode

def _norm(v):
    if isinstance(v, str) and v.startswith("0x") and len(v) == 42:
        return v.lower()
    if isinstance(v, (list, tuple)):
        return [_norm(x) for x in v]
    return v


def test_decode_matches_eth_abi_oracle():
    cases = [
        (["address", "uint256"], [A, 12345]),
        (["bytes32", "uint256"], [H32, 2 ** 200]),
        (["bool", "string", "bytes"], [False, "héllo", "0x"]),
        (["address[]", "uint256[]"], [[A, B], [1, 2, 3]]),
        (["uint256[2][3]"], [[[1, 2], [3, 4], [5, 6]]]),
        (["bytes[]"], [["0x11", "0x2233"]]),
        (["int256"], [-(2 ** 200)]),
        (["uint256[][]"], [[[1, 2], [3]]]),
        (["string[2]"], [["a", "b"]]),
        (["bytes32[2]"], [[H32, H32]]),
        ([], []),
    ]
    for types, vals in cases:
        enc = "0x" + eth_encode(types, _oracle_vals(types, vals)).hex()
        mine = abi.decode_abi(types, enc)
        ref = _from_oracle(eth_decode(types, bytes.fromhex(enc[2:])))
        assert _norm(mine) == _norm(ref), types


def _from_oracle(v):
    """Recursively convert eth_abi's return forms to ours."""
    if isinstance(v, bytes):
        return "0x" + v.hex()
    if isinstance(v, (list, tuple)):
        return [_from_oracle(x) for x in v]
    return v


def test_decode_rejects_truncated():
    with pytest.raises(abi.AbiError):
        abi.decode_abi(["uint256"], "0x1234")
    with pytest.raises(abi.AbiError):
        abi.decode_abi(["bool"], "0x" + (2).to_bytes(32, "big").hex())
    with pytest.raises(abi.AbiError):
        # Dirty high bits on an address word.
        abi.decode_abi(["address"], "0x" + "ff" * 12 + "11" * 20)


def test_encode_decode_roundtrip():
    types = ["address", "bytes32", "uint256[]", "string"]
    vals = [A, H32, [1, 2, 3], "nightspire"]
    assert _norm(abi.decode_abi(
        types, "0x" + abi.encode_args(types, vals).hex())) == _norm(vals)


# ------------------------------------------------------------ daemon fixtures

def _daemon(tmp_path, monkeypatch, policy_extra=None, rpc_cls=None):
    from spellbook.daemon import Daemon
    seed_hex = "42" * 32
    (tmp_path / "seed.key").write_text(seed_hex)
    (tmp_path / "seed.key").chmod(0o600)
    cfg = {"seed_path": str(tmp_path / "seed.key"),
           "evm": {"chains": {"evm-46630": {"enabled": True,
                                            "rpc_url": "http://fake"}}}}
    policy = {"auto_approve_below": {"evm-46630:native": 10 ** 30}}
    if policy_extra:
        policy.update(policy_extra)
    for name, data in (("spellbook.json", json.dumps(cfg)),
                       ("policy.json", json.dumps(policy)),
                       ("request.token", "aa" * 32),
                       ("approve.token", "bb" * 32),
                       ("ledger.jsonl", "")):
        p = tmp_path / name
        p.write_text(data)
        p.chmod(0o600)
    monkeypatch.setattr(evm, "Rpc", rpc_cls or _FakeRpc)
    d = Daemon(str(tmp_path))
    # The daemon's KDF-mode key differs from the raw seed bytes — the fake
    # must expect the CREATE address for the daemon's actual sender.
    _FakeRpc.sender = d._evm_key("evm-46630")[1]
    return d


class _FakeRpc:
    """Stands in for evm.Rpc: canned chain, nonce, estimate, receipt.

    ``sender`` is set by _daemon() to the daemon's real derived address so
    the canned receipt's contractAddress matches CREATE(sender, nonce).
    """

    sender = None

    def __init__(self, url):
        self.url = url
        self.sent = []
        self.eth_calls = []

    def chain_id(self):
        return 46630

    def nonce(self, addr):
        return 7

    def gas_price_wei(self):
        return 10 ** 9

    def estimate_gas_call(self, *a):
        return 120_000

    def estimate_gas_deploy(self, *a):
        return 1_200_000

    def send_raw_tx(self, raw):
        self.sent.append(raw)
        return "0x" + "ab" * 32

    def receipt(self, tx_hash):
        return {"status": "0x1", "blockNumber": "0x64",
                "contractAddress": self._expected_deploy_addr(),
                "logs": [{"topics": ["0x" + "cc" * 32]}]}

    def wait_receipt(self, tx_hash, timeout=90, poll=1.0):
        return self.receipt(tx_hash)

    def eth_call(self, to, data_hex, from_addr=None, block="latest"):
        self.eth_calls.append((to, data_hex, from_addr))
        # getLock() -> (uint256 amount) = 5000
        return "0x" + (5000).to_bytes(32, "big").hex()

    def _expected_deploy_addr(self):
        from spellbook import evm as evm_mod
        return evm_mod.contract_address_from_deploy(type(self).sender, 7)


def _deploy_params(**over):
    p = {"intent": "contract_deploy", "chain": "evm-46630",
         "bytecode": "0x6080604052",
         "constructor_args": [],
         "purpose": "test deploy"}
    p.update(over)
    return p


def _call_params(**over):
    p = {"intent": "contract_call", "chain": "evm-46630",
         "contract": A, "method": "lock",
         "method_abi": {"name": "lock", "stateMutability": "payable",
                        "inputs": [{"name": "hashlock", "type": "bytes32"},
                                   {"name": "timelock", "type": "uint256"}]},
         "args": [H32, 7200], "value_wei": 5000,
         "purpose": "test lock"}
    p.update(over)
    return p


def _view_params(**over):
    p = {"intent": "contract_call_view", "chain": "evm-46630",
         "contract": A, "method": "getLock",
         "method_abi": {"name": "getLock", "stateMutability": "view",
                        "inputs": [],
                        "outputs": [{"name": "amount", "type": "uint256"}]},
         "args": []}
    p.update(over)
    return p


# ------------------------------------------------------------ validation

def test_deploy_validation(tmp_path, monkeypatch):
    d = _daemon(tmp_path, monkeypatch)
    # Unknown fields rejected (S13).
    with pytest.raises(evm.EvmError):
        d._validate_contract_deploy(_deploy_params(fee_mojos=1))
    with pytest.raises(evm.EvmError):
        d._validate_contract_deploy(_deploy_params(chain="evm-99999"))
    with pytest.raises(evm.EvmError):
        d._validate_contract_deploy(_deploy_params(bytecode="6080"))
    with pytest.raises(evm.EvmError):
        d._validate_contract_deploy(_deploy_params(bytecode="0xzzzz"))
    with pytest.raises(evm.EvmError):
        d._validate_contract_deploy(_deploy_params(bytecode="0x"))
    with pytest.raises(evm.EvmError):
        d._validate_contract_deploy(
            _deploy_params(bytecode="0x" + "ff" * 49153))
    with pytest.raises(evm.EvmError):
        d._validate_contract_deploy(_deploy_params(value_wei=-1))
    with pytest.raises(evm.EvmError):
        d._validate_contract_deploy(_deploy_params(value_wei=True))
    with pytest.raises(evm.EvmError):
        d._validate_contract_deploy(_deploy_params(gas_limit=0))
    with pytest.raises(evm.EvmError):
        d._validate_contract_deploy(_deploy_params(gas_limit=10 ** 9))
    # Constructor args must match the ABI — refused BEFORE queueing.
    with pytest.raises(evm.EvmError):
        d._validate_contract_deploy(_deploy_params(
            constructor_args=[1],
            constructor_abi={"inputs": [{"name": "a", "type": "uint256"},
                                        {"name": "b", "type": "uint256"}]}))
    with pytest.raises(evm.EvmError):
        d._validate_contract_deploy(_deploy_params(
            constructor_args=["not-an-int"],
            constructor_abi={"inputs": [{"name": "a", "type": "uint256"}]}))
    # Happy path normalizes.
    intent = d._validate_contract_deploy(_deploy_params(gas_limit=500_000))
    assert intent["gas_limit"] == 500_000
    assert intent["value_wei"] == 0
    assert "constructor_abi" not in intent  # absent stays absent


def test_call_validation(tmp_path, monkeypatch):
    d = _daemon(tmp_path, monkeypatch)
    with pytest.raises(evm.EvmError):
        d._validate_contract_call(_call_params(contract="0x123"),
                                  view=False)
    with pytest.raises(evm.EvmError):
        d._validate_contract_call(_call_params(method="other"), view=False)
    with pytest.raises(evm.EvmError):
        d._validate_contract_call(_call_params(chain="chia"), view=False)
    # A view method sent as a transaction is caller confusion — refused.
    with pytest.raises(evm.EvmError):
        d._validate_contract_call(_view_params(intent="contract_call"),
                                  view=False)
    # A state-changing method via the read-only route is refused.
    with pytest.raises(evm.EvmError):
        d._validate_contract_call(_call_params(
            intent="contract_call_view"), view=True)
    # Args must match the ABI.
    with pytest.raises(evm.EvmError):
        d._validate_contract_call(_call_params(args=[H32]), view=False)
    with pytest.raises(evm.EvmError):
        d._validate_contract_call(
            _call_params(args=["0x123", 7200]), view=False)
    # Unknown fields rejected.
    with pytest.raises(evm.EvmError):
        d._validate_contract_call(_call_params(extra=1), view=False)
    # Undeclared stateMutability is lenient (ABI fragments vary).
    p = _call_params()
    del p["method_abi"]["stateMutability"]
    assert d._validate_contract_call(p, view=False)["method"] == "lock"


def test_evm_deploy_signer_to_is_empty():
    """sign_legacy_deploy signs a creation tx: RLP `to` is empty and the
    result's to is None. Cross-checked against CREATE address math."""
    priv = bytes.fromhex("42" * 32)
    signed = evm.sign_legacy_deploy(priv, 46630, 7, 0, "0x60806040",
                                    10 ** 9, 100_000)
    assert signed["to"] is None
    sender = evm.address_from_privkey(priv)
    assert signed["from"] == sender
    # The RLP to field must be the empty string (0x80), not 20 zero bytes.
    raw = bytes.fromhex(signed["raw_hex"][2:])
    assert b"\x94" + b"\x00" * 20 not in raw  # no zero-address `to`
    assert evm.contract_address_from_deploy(sender, 7).startswith("0x")
    assert len(evm.contract_address_from_deploy(sender, 7)) == 42


# ------------------------------------------------------------ queue behavior

def test_deploy_and_call_always_queue(tmp_path, monkeypatch):
    """Arbitrary code is a capability: deploy/call always queue for a
    human even under a permissive policy — never auto-approved."""
    d = _daemon(tmp_path, monkeypatch)
    r = d.rt_contract_deploy(_deploy_params(), "muse_test")
    assert r["ok"] and r["decision"] == "queued"
    r = d.rt_contract_call(_call_params(), "muse_test")
    assert r["ok"] and r["decision"] == "queued"
    # Zero-value calls queue too (0-value calldata can still approve
    # spenders — value thresholds are the wrong control).
    r = d.rt_contract_call(_call_params(value_wei=0), "muse_test")
    assert r["ok"] and r["decision"] == "queued"
    assert len(d.queue) == 3


def test_queue_display_decodes_contract_intents(tmp_path, monkeypatch):
    """The human sees the DECODED call — contract, method, args, value —
    never raw calldata; deploys show NEW CONTRACT + bytecode digest."""
    d = _daemon(tmp_path, monkeypatch)
    d.rt_contract_deploy(_deploy_params(constructor_args=[],
                                        purpose="deploy escrow"), "muse_test")
    d.rt_contract_call(_call_params(), "muse_test")
    q = d._decoded_queue()
    dep, call = q[0], q[1]
    assert dep["kind"] == "contract_deploy" and dep["new_contract"] is True
    assert dep["bytecode_len"] == 5
    assert len(dep["bytecode_sha256"]) == 64
    assert dep["purpose"] == "deploy escrow"
    assert call["kind"] == "contract_call"
    assert call["contract"] == A and call["method"] == "lock"
    assert call["args"] == [H32, 7200]
    assert call["value_wei"] == 5000


def test_view_needs_no_queue(tmp_path, monkeypatch):
    """contract_call_view: no queue entry, no ledger line, decoded result."""
    d = _daemon(tmp_path, monkeypatch)
    r = d.rt_contract_call_view(_view_params(), "muse_test")
    assert r["ok"] is True
    assert r["value"] == 5000 and r["result"] == [5000]
    assert r["method"] == "getLock"
    assert len(d.queue) == 0
    assert d.ledger.read_all() == []


def test_view_refuses_unconfigured_chain(tmp_path, monkeypatch):
    d = _daemon(tmp_path, monkeypatch)
    d.evm_cfg["chains"]["evm-46630"]["enabled"] = False
    r = d.rt_contract_call_view(_view_params(), "muse_test")
    assert r["ok"] is False and "not configured" in r["error"]


# ------------------------------------------------------------ execution

def test_deploy_executes_on_approval(tmp_path, monkeypatch):
    """One approval = one execution: the approved deploy broadcasts, the
    receipt's contractAddress is cross-checked against CREATE math, and
    the response carries the verified address."""
    d = _daemon(tmp_path, monkeypatch)
    r = d.rt_contract_deploy(_deploy_params(), "muse_test")
    qid = r["queue_id"]
    out = d.rt_queue_approve({"queue_id": qid}, "human")
    assert out["ok"] is True
    assert out["tx_hash"] == "0x" + "ab" * 32
    _, sender = d._evm_key("evm-46630")
    assert out["contract_address"] == \
        evm.contract_address_from_deploy(sender, 7)
    # The queue item is consumed: one approval bought one execution.
    assert qid not in d.queue
    decisions = [row["decision"] for row in d.ledger.read_all()]
    assert "approved-by-human" in decisions
    # A deploy moves no asset — no velocity leg.
    assert d.spent_last_24h("evm-46630", "native") == 0


def test_call_executes_on_approval_and_records_velocity(tmp_path, monkeypatch):
    d = _daemon(tmp_path, monkeypatch)
    r = d.rt_contract_call(_call_params(), "muse_test")
    out = d.rt_queue_approve({"queue_id": r["queue_id"]}, "human")
    assert out["ok"] is True
    assert out["tx_hash"] == "0x" + "ab" * 32
    assert out["block"] == 0x64
    assert out["logs"] == [{"topics": ["0x" + "cc" * 32]}]
    # The value leg counts toward velocity.
    assert d.spent_last_24h("evm-46630", "native") == 5000


def test_explicit_gas_limit_used_verbatim(tmp_path, monkeypatch):
    """An approved explicit gas_limit is used as-is (no node estimate)."""
    seen = {}

    class _GasRpc(_FakeRpc):
        def estimate_gas_deploy(self, *a):
            seen["estimated"] = True
            return super().estimate_gas_deploy(*a)

    monkeypatch.setattr(evm, "Rpc", _GasRpc)
    d = _daemon(tmp_path, monkeypatch)
    r = d.rt_contract_deploy(_deploy_params(gas_limit=900_000), "muse_test")
    out = d.rt_queue_approve({"queue_id": r["queue_id"]}, "human")
    assert out["ok"] is True
    assert "estimated" not in seen


def test_deploy_refuses_mainnet_without_flag(tmp_path, monkeypatch):
    """Mainnet contract deploys need the separately-authorized
    mainnet_submit_enabled flag — same gate as every EVM submission."""
    from spellbook import evm as evm_mod
    monkeypatch.setitem(evm_mod.CHAINS, "evm-4663",
                        {"chain_id": 4663, "testnet": False,
                         "name": "Robinhood Chain"})

    class _MainnetRpc(_FakeRpc):
        def chain_id(self):
            return 4663

    monkeypatch.setattr(evm, "Rpc", _MainnetRpc)
    d = _daemon(tmp_path, monkeypatch)
    d.evm_cfg["chains"]["evm-4663"] = {"enabled": True,
                                       "rpc_url": "http://fake"}
    r = d.rt_contract_deploy(_deploy_params(chain="evm-4663"), "muse_test")
    assert r["decision"] == "queued"  # queues fine...
    out = d.rt_queue_approve({"queue_id": r["queue_id"]}, "human")
    assert out["ok"] is False  # ...but execution refuses mainnet
    assert "mainnet_submit_enabled" in out["error"]


def test_deploy_receipt_address_mismatch_refuses(tmp_path, monkeypatch):
    """A receipt whose contractAddress does not match CREATE(sender, nonce)
    is refused — the daemon never reports an unverified address."""

    class _LyingRpc(_FakeRpc):
        def receipt(self, tx_hash):
            rc = super().receipt(tx_hash)
            rc["contractAddress"] = "0x" + "ff" * 20
            return rc

    d = _daemon(tmp_path, monkeypatch, rpc_cls=_LyingRpc)
    r = d.rt_contract_deploy(_deploy_params(), "muse_test")
    out = d.rt_queue_approve({"queue_id": r["queue_id"]}, "human")
    assert out["ok"] is False
    assert "contractAddress" in out["error"]


# ------------------------------------------------------------ client + CLI

class _ProbeClient:
    """Captures AgentClient routes/params without a socket."""

    def __init__(self):
        from spellbook.client import AgentClient
        self.seen = None
        self._c = AgentClient.__new__(AgentClient)

        def _call(route, params=None, timeout=None):
            self.seen = {"route": route, "params": params}
            return {"ok": True}

        self._c._call = _call

    def __getattr__(self, name):
        return getattr(self._c, name)


def test_client_routes_contract_intents():
    p = _ProbeClient()
    p.contract_deploy(chain="evm-46630", bytecode="0x6080",
                      constructor_args=[1],
                      constructor_abi={"inputs": [{"name": "a",
                                                  "type": "uint256"}]},
                      purpose="probe")
    assert p.seen["route"] == "contract_deploy"
    params = p.seen["params"]
    assert params["intent"] == "contract_deploy"
    assert params["constructor_args"] == [1]
    assert "gas_limit" not in params  # omitted, not sent as None

    p.contract_call(chain="evm-46630", contract=A, method="lock",
                    method_abi={"name": "lock"}, args=[1], value_wei=5,
                    purpose="probe")
    assert p.seen["route"] == "contract_call"
    assert p.seen["params"]["value_wei"] == 5

    p.contract_call_view(chain="evm-46630", contract=A, method="getLock",
                         method_abi={"name": "getLock"})
    assert p.seen["route"] == "contract_call_view"
    assert p.seen["params"]["args"] == []


def test_cli_contract_commands_wire_params(capsys):
    """The CLI parses JSON args/ABI and forwards decoded params — the
    human-readable surface the onboarding doc teaches."""
    import argparse
    from spellbook import cli

    ns = argparse.Namespace(
        chain="evm-46630", bytecode="0x6080", constructor_args="[7]",
        constructor_abi='{"inputs":[{"name":"a","type":"uint256"}]}',
        value_wei=0, gas_limit=None, purpose="probe")
    probe = _ProbeClient()
    cli.cmd_contract_deploy(ns, probe)
    assert probe.seen["route"] == "contract_deploy"
    assert probe.seen["params"]["constructor_args"] == [7]

    ns = argparse.Namespace(
        chain="evm-46630", contract=A, method="lock",
        method_abi='{"name":"lock","stateMutability":"payable",'
                   '"inputs":[{"name":"v","type":"uint256"}]}',
        args="[5]", value_wei=5, gas_limit=None, purpose="probe")
    cli.cmd_contract_call(ns, probe)
    assert probe.seen["route"] == "contract_call"
    assert probe.seen["params"]["args"] == [5]

    ns = argparse.Namespace(
        chain="evm-46630", contract=A, method="getLock",
        method_abi='{"name":"getLock","stateMutability":"view",'
                   '"inputs":[],"outputs":[{"name":"x","type":"uint256"}]}',
        args=None)
    cli.cmd_contract_call_view(ns, probe)
    assert probe.seen["route"] == "contract_call_view"
    assert probe.seen["params"]["args"] == []

    # Malformed JSON fails at the CLI, before any daemon call.
    bad = argparse.Namespace(
        chain="evm-46630", contract=A, method="lock",
        method_abi="{bad json", args=None, value_wei=0, gas_limit=None,
        purpose="")
    with pytest.raises(SystemExit):
        cli.cmd_contract_call(bad, probe)


def test_base_sepolia_accepted_for_contract_intents(tmp_path, monkeypatch):
    """The cross-chain HTLC flow needs evm-84532 (Base Sepolia): deploy,
    call, and view intents must all validate on it."""
    d = _daemon(tmp_path, monkeypatch)
    dep = _deploy_params(chain="evm-84532")
    assert d._validate_contract_deploy(dep)["chain"] == "evm-84532"
    call = _call_params(chain="evm-84532")
    assert d._validate_contract_call(call, view=False)["chain"] == "evm-84532"
    view = _view_params(chain="evm-84532")
    assert d._validate_contract_call(view, view=True)["chain"] == "evm-84532"
