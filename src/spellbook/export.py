"""`spellbook export` — the human-only paper backup (SPEC §6, S3; review S-05).

The installer used to print both mnemonics, every raw private key and the
request token to its stdout. Agents run the installer, so those secrets
landed in tool output, transcripts and logs. Now:

  - the installer never prints a secret; the paper backup is shown only by
    this command, and only on a real terminal (stdin AND stdout are TTYs);
  - the words go to /dev/tty, never to stdout, with an explicit pause and a
    screen clear afterwards (scrollback included where the terminal honors
    ANSI 3J; `tput clear` is run as well);
  - the command refuses to run for the agent's OS user (the UIDs the config
    allows on the request token) and without a TTY — exit non-zero with a
    message; it refuses silently to no one;
  - raw private keys are never shown: the words recover everything the
    daemon derives (SET 1 in stock wallets; SET 2 through the daemon).

The decision logic is pure (`export_guard`, `paper_backup_text`) so it is
tested without a terminal, a daemon or a real seed.
"""
import json
import os
import shutil
import subprocess
import sys

from spellbook import kdf
from spellbook.seed import load_seed, mnemonic_from_entropy

CLEAR_SEQUENCE = "\x1b[2J\x1b[3J\x1b[H"


class ExportRefused(SystemExit):
    """Raised with a human-readable reason; exit status 3."""

    def __init__(self, reason: str):
        super().__init__(3)
        self.reason = reason


def export_guard(stdin_is_tty: bool, stdout_is_tty: bool, login_uid: int | None,
                 agent_uids: list[int] | None) -> str | None:
    """Why the backup must NOT be shown, or None when it may be.

    `login_uid` is the human behind the terminal: $SUDO_UID under sudo,
    else the real uid. `agent_uids` are the request-token UIDs from the
    daemon config (the agent's OS user).
    """
    if not (stdin_is_tty and stdout_is_tty):
        return ("no terminal: stdin and stdout must both be a TTY. The paper "
                "backup is never written to a pipe, a log or a tool's output "
                "(S3). Run `spellbook export` yourself, from your own login.")
    if login_uid is None:
        return "cannot determine the login user (POSIX only)"
    if agent_uids and login_uid in agent_uids:
        return (f"login uid {login_uid} is the agent's OS user "
                "(allowed_request_uids). The paper backup is for the human "
                "only — the agent must never see it (S3).")
    return None


def login_uid() -> int | None:
    sudo_uid = os.environ.get("SUDO_UID", "").strip()
    if sudo_uid.isdigit():
        return int(sudo_uid)
    getuid = getattr(os, "getuid", None)
    return getuid() if getuid else None


def _std_addresses(std_entropy: bytes) -> dict:
    from spellbook import chia_sign, stdkeys
    from spellbook import solana as solana_mod
    seed64 = stdkeys.mnemonic_to_seed(mnemonic_from_entropy(std_entropy))
    master = stdkeys.chia_master_sk(seed64)
    sol = solana_mod.standard_keypair(seed64)
    return {
        "evm": stdkeys.evm_address(stdkeys.evm_privkey(seed64)),
        "chia-testnet": chia_sign.receive_address(master, 0, "testnet11"),
        "chia-mainnet": chia_sign.receive_address(master, 0, "mainnet"),
        "solana": solana_mod.address_of_keypair(sol),
    }


def _kdf_addresses(seed: bytes) -> dict:
    from spellbook import chia_sign
    from spellbook import solana as solana_mod
    out = {}
    for chain in ("evm-4663", "evm-46630"):
        out[chain] = kdf.derive_labeled(seed, chain, "default")["address"]
    for chain, net in (("chia-testnet", "testnet11"), ("chia-mainnet", "mainnet")):
        sk = bytes.fromhex(kdf.derive_labeled(seed, chain, "default")["scalar_hex"])
        out[chain] = chia_sign.receive_address(sk, 0, net)
    for chain in ("solana-devnet", "solana-mainnet"):
        out[chain] = solana_mod.address_of_keypair(
            solana_mod.custom_keypair(seed, chain, "default"))
    return out


def paper_backup_text(kdf_seed: bytes | None, std_entropy: bytes | None,
                      with_addresses: bool = True) -> str:
    """The once-only paper backup: words only, never raw keys."""
    if kdf_seed is None and std_entropy is None:
        raise ValueError("nothing to export: no seed on this install")
    lines = [
        "================================================================",
        "PAPER BACKUP (SPEC §6) — write these down NOW, on paper, offline.",
        "Shown on this terminal only, then cleared. Two copies, two places.",
        "Anyone holding EITHER set of words holds the wallet.",
        "No raw private keys are shown: the words recover everything.",
        "================================================================",
    ]
    if std_entropy is not None:
        lines += [
            "",
            "SET 1 — STANDARD RECOVERY (primary: the daemon's live keys).",
            "Import these 24 words into Sage (Chia), MetaMask (EVM) or",
            "Phantom (Solana) and the first address matches the one below.",
            "",
            "  " + mnemonic_from_entropy(std_entropy),
        ]
        if with_addresses:
            a = _std_addresses(std_entropy)
            lines += ["", f"  EVM (every chain)   {a['evm']}",
                      f"  Chia testnet11      {a['chia-testnet']}",
                      f"  Chia mainnet        {a['chia-mainnet']}",
                      f"  Solana (any net)    {a['solana']}"]
    if kdf_seed is not None:
        lines += [
            "",
            "SET 2 — SPELLBOOK DAEMON SEED (custom KDF — secondary recovery).",
            "These 24 words recover through the Spellbook daemon ONLY; they",
            "do NOT work in Sage/MetaMask/Phantom.",
            "",
            "  " + mnemonic_from_entropy(kdf_seed),
        ]
        if with_addresses:
            a = _kdf_addresses(kdf_seed)
            lines += [""] + [f"  {chain:<18}  {addr}" for chain, addr in a.items()]
    lines += ["", "Verify after any import: the addresses must match what the",
              "wallet shows. Press Enter after you have written these down;",
              "the screen is cleared then."]
    return "\n".join(lines) + "\n"


def _agent_uids(prefix: str) -> list[int]:
    try:
        with open(os.path.join(prefix, "spellbook.json")) as f:
            cfg = json.load(f)
    except (OSError, ValueError):
        return []
    uids = cfg.get("allowed_request_uids") or []
    return [u for u in uids if isinstance(u, int)]


def run_export(prefix: str, tty_path: str = "/dev/tty") -> int:
    """The CLI body. Returns the exit status; prints reasons to stderr."""
    reason = export_guard(sys.stdin.isatty(), sys.stdout.isatty(),
                          login_uid(), _agent_uids(prefix))
    if reason:
        print(f"spellbook export: refused — {reason}", file=sys.stderr)
        return 3
    seed_path = os.path.join(prefix, "seed.key")
    std_entropy_path = os.path.join(prefix, "std_entropy.key")
    kdf_seed = load_seed(seed_path) if os.path.exists(seed_path) else None
    std_entropy = (load_seed(std_entropy_path)
                   if os.path.exists(std_entropy_path) else None)
    try:
        text = paper_backup_text(kdf_seed, std_entropy)
    except ValueError as e:
        print(f"spellbook export: {e}", file=sys.stderr)
        return 2
    # The words go to the terminal device itself, never to stdout.
    with open(tty_path, "w") as tty_out, open(tty_path) as tty_in:
        tty_out.write("\n" + text)
        tty_out.flush()
        tty_in.readline()
        tty_out.write(CLEAR_SEQUENCE)
        tty_out.flush()
    if shutil.which("tput"):
        subprocess.run(["tput", "clear"], check=False)
    print("spellbook export: paper backup shown once and cleared.")
    return 0
