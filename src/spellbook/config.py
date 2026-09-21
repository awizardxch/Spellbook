"""Config loading — daemon-user-owned files, mode 600, fail closed.

spellbook.json (all fields optional unless noted):
  musebook_signing_mode : "disabled" | "daemon"   (default "disabled"; S1 gate)
  seed_path             : path to the 32-byte hex seed file (optional —
                          without it the daemon serves policy/queue/ledger
                          but derives no addresses)
  labels                : [label, ...] to derive addresses for (default ["default"])
  chia_enabled          : bool (default true; false with install.sh --no-sage)
  sage_bin              : path to the verified sage CLI binary built from the
                          pinned commit (install.sh §2); null with --no-sage
  socket_group          : Unix group allowed to connect to the socket (optional —
                          without it the socket is 0700, daemon user only)
  allowed_request_uids  : [uid, ...] allowed to use the request token (optional —
                          when set, the kernel peer UID is ENFORCED, not observed)
  allowed_approve_uids  : [uid, ...] allowed to use the approve token (optional)

policy.json: the D9 default-off policy knobs, keyed "chain:asset".
"""
import json
import os

from spellbook.policy import Policy


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
