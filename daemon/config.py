"""Config loading — daemon-user-owned files, mode 600, fail closed."""
import json
import os

from policy import Policy


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
