"""Config loading — daemon-user-owned files, mode 600, fail closed.

spellbook.json (all fields optional unless noted):
  musebook_signing_mode : "disabled" | "daemon"   (default "disabled"; S1 gate)
  seed_path             : path to the 32-byte hex seed file (optional —
                          without it the daemon serves policy/queue/ledger
                          but derives no addresses)
  key_derivation        : "kdf" | "standard" (default "kdf"). "kdf" keeps the
                          daemon's custom labeled KDF (existing wallets
                          untouched). "standard" makes the daemon derive and
                          sign with the standards-based wallet instead: Chia
                          via BLS key_gen (Sage-compatible), EVM via BIP-32
                          m/44'/60'/0'/0/0 (MetaMask-compatible) — SPEC §2b.
  std_seed_path         : path to the 64-byte BIP-39 seed file (128 hex
                          chars, 0600). Required when key_derivation is
                          "standard"; the daemon refuses to start in
                          standard mode without it.
  labels                : [label, ...] to derive addresses for (default ["default"])
  chia_enabled          : bool (default true; false with install.sh --no-sage)
  sage_bin              : path to the verified sage CLI binary built from the
                          pinned commit (install.sh §2); null with --no-sage
  chia                  : {"sage_bin": str, "sage_data_home": str,
                          "rpc_port": int (default 9257),
                          "fee_mojos": int (default 0),
                          "network": "testnet11" | "mainnet" (default
                              "testnet11" — the active network; the default
                              flips to mainnet once mainnet is authorized),
                          "relay_urls": {"testnet11": url, "mainnet": url}
                              (per-network relay URLs; legacy flat
                              "relay_url" still works as a fallback),
                          "mainnet_submit_enabled": bool (default false),
                          "sage_cert_fingerprint": 64-hex (optional — the
                              SHA-256 of Sage's ssl/wallet.crt (DER),
                              recorded by `spellbook sage-provision`; the
                              daemon refuses any RPC listener whose
                              certificate does not match it, and refuses
                              to start Sage if wallet.crt on disk no longer
                              matches it. Without it the on-disk wallet.crt
                              alone is the pin),
                          "sage_runtime_key_import": bool (default false —
                              UNSAFE legacy behavior: lets the daemon
                              /import_key the master key at runtime when
                              Sage lacks the fingerprint. Leave off; run
                              `spellbook sage-provision` once instead),
                          "max_offer_fee_mojos": int (default 50_000_000 —
                              upper bound on the fee_mojos an offer or any
                              other Sage intent may request; the fee is
                              also counted against native policy caps)} —
                          Sage wiring (§10 phase 1); {} or missing with
                          --no-sage. The daemon spawns `sage rpc start` with
                          XDG_DATA_HOME=sage_data_home when the RPC port is
                          silent; Sage keeps its DB + mTLS certs at
                          <sage_data_home>/com.rigidnetwork.sage. The
                          server certificate is verified (wallet.crt is the
                          trust anchor) and pinned on every connection.
                          One seed serves both networks: the KDF derives
                          per-chain keys and only the bech32m HRP differs
                          (txch1 vs xch1), so the paper backup covers both.
  socket_group          : Unix group allowed to connect to the socket (optional —
                          without it the socket is 0700, daemon user only)
  dex                   : {"recommended_venues": ["matcha", "uniswap"]} (optional —
                          default both). The user's recommended swap venues
                          (SPEC §10 v2) — advisory, not a gate: a dex_swap
                          intent naming any other venue is queued with a
                          prominent warning, and the human's per-transaction
                          approval is what authorizes the venue. Every
                          agent's human approves their own venues. "0x" is
                          accepted as an alias for "matcha" (the 0x Swap
                          API, matcha.xyz's engine). Unknown names fail the
                          daemon at startup. Takes effect on daemon restart.
  solana                : {"network": "devnet" | "mainnet-beta" (default
                          "devnet" — the active network),
                          "rpc_url": str (optional — defaults to the
                          network's public HTTPS endpoint),
                          "mainnet_submit_enabled": bool (default false)} —
                          direct JSON-RPC to a public node (no relay; the
                          endpoint sees public addresses, balances, and
                          already-signed transactions only). A spend for the
                          non-active network is refused before any policy
                          evaluation (fail closed); spends for
                          solana-mainnet additionally need
                          mainnet_submit_enabled. Amounts are lamports
                          (asset "SOL").
  allowed_request_uids  : [uid, ...] allowed to use the request token (f-04:
                          default-on — when absent, ALL requests fail closed;
                          the kernel peer UID is ENFORCED, not observed)
  allowed_approve_uids  : [uid, ...] allowed to use the approve token (same)

policy.json: the D9 default-off policy knobs, keyed "chain:asset".
"""
import json
import os
import re

from spellbook.policy import Policy

# Upper bound on fee_mojos for offers and every other Sage intent that takes
# a fee (chia.max_offer_fee_mojos). 0.05 XCH: generous for any real fee,
# far below anything worth burning to farmers.
DEFAULT_MAX_OFFER_FEE_MOJOS = 50_000_000


def _must_600(path: str):
    st = os.stat(path)
    if st.st_mode & 0o077:
        raise PermissionError(f"{path} is not 0600 — refusing to start")


def load_config(config_dir: str) -> dict:
    cfg_path = os.path.join(config_dir, "spellbook.json")
    _must_600(cfg_path)
    with open(cfg_path) as f:
        cfg = json.load(f)
    # S1: daemon-side Musebook signing is INERT until Speechless decides.
    cfg.setdefault("musebook_signing_mode", "disabled")  # "disabled" | "daemon"
    if cfg["musebook_signing_mode"] not in ("disabled", "daemon"):
        raise ValueError("musebook_signing_mode must be 'disabled' or 'daemon'")
    cfg.setdefault("labels", ["default"])
    cfg.setdefault("chia_enabled", True)
    for key in ("allowed_request_uids", "allowed_approve_uids"):
        if key in cfg and not all(isinstance(u, int) for u in cfg[key]):
            raise ValueError(f"{key} must be a list of integer UIDs")
    chia_cfg = cfg.get("chia") or {}
    if not isinstance(chia_cfg, dict):
        raise ValueError("chia must be an object")
    fp = chia_cfg.get("sage_cert_fingerprint")
    if fp is not None and not (isinstance(fp, str)
                               and re.fullmatch(r"[0-9a-fA-F]{64}", fp)):
        raise ValueError(
            "chia.sage_cert_fingerprint must be the 64-hex SHA-256 of "
            "Sage's wallet.crt")
    if not isinstance(chia_cfg.get("sage_runtime_key_import", False), bool):
        raise ValueError("chia.sage_runtime_key_import must be a boolean")
    mx = chia_cfg.get("max_offer_fee_mojos", DEFAULT_MAX_OFFER_FEE_MOJOS)
    if isinstance(mx, bool) or not isinstance(mx, int) or mx < 0:
        raise ValueError("chia.max_offer_fee_mojos must be a non-negative "
                         "integer")
    return cfg


def load_policy(config_dir: str) -> Policy:
    pol_path = os.path.join(config_dir, "policy.json")
    _must_600(pol_path)
    with open(pol_path) as f:
        raw = json.load(f)
    allow = {}
    for k, v in raw.get("destination_allowlist", {}).items():
        chain, asset = k.split(":", 1)
        allow[(chain, asset)] = set(v)

    def keyed(d):
        return {(k.split(":", 1)[0], k.split(":", 1)[1]): v for k, v in d.items()}

    return Policy(
        per_spend_cap=keyed(raw.get("per_spend_cap", {})),
        approval_threshold=keyed(raw.get("approval_threshold", {})),
        auto_approve_below=keyed(raw.get("auto_approve_below", {})),
        daily_velocity_cap=keyed(raw.get("daily_velocity_cap", {})),
        destination_allowlist=allow,
    )
