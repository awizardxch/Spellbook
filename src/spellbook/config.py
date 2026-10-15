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
  allowed_request_uids  : [uid, ...] allowed to use the request token (optional —
                          when set, the kernel peer UID is ENFORCED, not observed)
  allowed_approve_uids  : [uid, ...] allowed to use the approve token (optional)
  seed_role             : "identity" | "wallet" (optional). What the seed at
                          seed_path is. "identity" = a Musebook identity
                          seed; "wallet" = a daemon-generated wallet root.
                          Unset = detected from the other markers
                          (seedrole.py): musebook_signing_mode=daemon, the
                          seed file's role header, or a seed_path that names
                          the Musebook client / a .env file.
  allow_identity_seed_as_wallet_root
                        : bool (default false). UNSAFE. Under
                          key_derivation=kdf the seed is the wallet root for
                          every chain; when it is also the Musebook identity
                          seed the daemon refuses to start (S1 is open —
                          review S-04). true accepts that knowingly: whoever
                          holds the identity seed holds every wallet key
                          offline. Never set it on a muse that signs from
                          more than one machine.
  dashboard_sign_per_minute
                        : int (default 30). Rate cap on sign_dashboard_challenge.

policy.json: the D9 default-off policy knobs, keyed "chain:asset".
"""
import json
import os
import re

from spellbook.policy import Policy
from spellbook.seedrole import ALLOW_KEY, SEED_ROLES

# Upper bound on fee_mojos for offers and every other Sage intent that takes
# a fee (chia.max_offer_fee_mojos). 0.05 XCH: generous for any real fee,
# far below anything an attacker could burn to farmers.
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
    # S-04: the seed's role and the unsafe opt-in are validated here so a
    # typo ("True", 1, "yes") can never read as consent.
    if cfg.get("seed_role") is not None and cfg["seed_role"] not in SEED_ROLES:
        raise ValueError("seed_role must be 'identity' or 'wallet'")
    cfg.setdefault(ALLOW_KEY, False)
    if cfg[ALLOW_KEY] is not True and cfg[ALLOW_KEY] is not False:
        raise ValueError(f"{ALLOW_KEY} must be true or false")
    cfg.setdefault("dashboard_sign_per_minute", 30)
    if (not isinstance(cfg["dashboard_sign_per_minute"], int)
            or cfg["dashboard_sign_per_minute"] < 1):
        raise ValueError("dashboard_sign_per_minute must be a positive integer")
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
