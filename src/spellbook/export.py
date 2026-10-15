"""`spellbook export` — the paper backup, off stdout (SPEC §6, S3; review S-05).

install.sh used to print both mnemonics, every raw private key and the
request token to its stdout and to a paper-backup.txt. Agents run the
installer, so those secrets landed in tool output, transcripts and logs.
Now the installer prints nothing secret, and the backup leaves the machine
one of two ways:

  terminal  (`spellbook export`) — for a human at a real terminal. The
            words go to /dev/tty, never to stdout, with a pause and a
            screen clear afterwards (ANSI 2J/3J plus `tput clear`). Then
            the human proves the SET 1 copy by typing 3 of its words back
            (what install.sh used to ask). Refuses without a TTY on both
            stdin and stdout, and refuses the agent's OS user (the UIDs the
            config allows on the request token).

  envelope  (`spellbook export --reveal-key <b64 SPKI>`) — for the seal
            ceremony (ceremony/seal-password-encryptor.html, Steps 1-2),
            where the human can only reach the agent. The human's page makes
            an RSA reveal key and hands the agent the PUBLIC half; this
            command encrypts the backup to it and prints only the envelope
            the page decrypts. The agent relays ciphertext and never sees a
            word. It must run with read access to the seed files (root or
            the spellbook user); it prints nothing secret, so it needs no
            terminal.

Raw private keys are never shown in either mode: the words recover
everything the daemon derives (SET 1 in stock wallets; SET 2 through the
daemon). The decision logic is pure (`export_guard`, `paper_backup_text`,
`seal_to_reveal_key`) so it is tested without a terminal, a daemon or a
real seed.
"""
import base64
import json
import os
import secrets
import shutil
import subprocess
import sys

from spellbook import kdf
from spellbook.seed import load_seed, mnemonic_from_entropy

CLEAR_SEQUENCE = "\x1b[2J\x1b[3J\x1b[H"
EXIT_REFUSED = 3
EXIT_NOT_VERIFIED = 4
VERIFY_WORDS = 3
VERIFY_ATTEMPTS = 3


def export_guard(stdin_is_tty: bool, stdout_is_tty: bool, login_uid: int | None,
                 agent_uids: list[int] | None) -> str | None:
    """Why the backup must NOT be shown on this terminal, or None when it may.

    `login_uid` is the human behind the terminal: $SUDO_UID under sudo,
    else the real uid. `agent_uids` are the request-token UIDs from the
    daemon config (the agent's OS user).
    """
    if not (stdin_is_tty and stdout_is_tty):
        return ("no terminal: stdin and stdout must both be a TTY. The paper "
                "backup is never written to a pipe, a log or a tool's output "
                "(S3). Run `spellbook export` yourself, from your own login, "
                "or use the seal ceremony (--reveal-key).")
    if login_uid is None:
        return "cannot determine the login user (POSIX only)"
    if agent_uids and login_uid in agent_uids:
        return (f"login uid {login_uid} is the agent's OS user "
                "(allowed_request_uids). The paper backup on a terminal is "
                "for the human only (S3); an agent relays it encrypted with "
                "--reveal-key instead.")
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
    from spellbook.stdkeys import mnemonic_to_seed
    seed64 = mnemonic_to_seed(mnemonic_from_entropy(std_entropy))
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
                      with_addresses: bool = True, *,
                      std_words_lost: bool = False,
                      terminal: bool = True) -> str:
    """The paper backup: words and addresses, never raw keys."""
    if kdf_seed is None and std_entropy is None:
        raise ValueError("nothing to export: no seed on this install")
    lines = [
        "================================================================",
        "PAPER BACKUP (SPEC §6) — write these down NOW, on paper, offline.",
        "Two copies, two places. Anyone holding EITHER set of words holds",
        "the wallet. No raw private keys are shown: the words recover",
        "everything.",
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
    elif std_words_lost:
        lines += [
            "",
            "SET 1 — STANDARD RECOVERY: not shown. This install has no",
            "std_entropy.key (it predates it, or was restored), and BIP-39",
            "words cannot be re-derived from std_seed.key. Only the paper",
            "copy made at install holds them. Seal the seed (spellbook-seed",
            "serve) so a wipe never depends on them.",
        ]
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
              "wallet shows."]
    if terminal:
        lines += ["Press Enter after you have written these down; the screen",
                  "is cleared then."]
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------- envelope

def _load_reveal_key(reveal_key_b64: str):
    # pycryptodome is already a pinned dependency (f-03); no new crypto lib.
    from Crypto.PublicKey import RSA
    try:
        der = base64.b64decode("".join(str(reveal_key_b64).split()), validate=True)
        key = RSA.import_key(der)
    except Exception:
        raise ValueError("reveal key must be the base64 SPKI RSA public key "
                         "the ceremony page shows (Step 1)")
    if key.has_private() or key.size_in_bits() < 2048:
        raise ValueError("reveal key must be an RSA PUBLIC key of at least 2048 bits")
    return key


def seal_to_reveal_key(text: str, reveal_key_b64: str) -> str:
    """Encrypt `text` for the ceremony page's reveal key.

    Format (ceremony/seal-password-encryptor.html, Step 2): base64 of JSON
    {k: b64 RSA-OAEP-SHA256(aes_key), n: b64 12-byte nonce,
     c: b64 AES-256-GCM(ciphertext || 16-byte tag)} — what WebCrypto's
    RSA-OAEP (SHA-256, MGF1-SHA-256) and AES-GCM decrypt.
    """
    from Crypto.Cipher import AES, PKCS1_OAEP
    from Crypto.Hash import SHA256
    key = _load_reveal_key(reveal_key_b64)
    aes_key = os.urandom(32)
    nonce = os.urandom(12)
    c = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    ct, tag = c.encrypt_and_digest(text.encode("utf-8"))
    wrapped = PKCS1_OAEP.new(key, hashAlgo=SHA256).encrypt(aes_key)
    env = {"k": base64.b64encode(wrapped).decode(),
           "n": base64.b64encode(nonce).decode(),
           "c": base64.b64encode(ct + tag).decode()}
    return base64.b64encode(json.dumps(env).encode()).decode()


# ---------------------------------------------------------------- verification

def verification_positions(n_words: int = 24, k: int = VERIFY_WORDS) -> list[int]:
    """k distinct 1-based word positions, chosen with the OS CSPRNG."""
    out: list[int] = []
    while len(out) < k:
        p = secrets.randbelow(n_words) + 1
        if p not in out:
            out.append(p)
    return out


def check_words(mnemonic: str, positions: list[int], answers: list[str]) -> bool:
    words = mnemonic.split()
    if len(answers) != len(positions):
        return False
    ok = True
    for p, a in zip(positions, answers):
        ok &= secrets.compare_digest(words[p - 1].encode(),
                                     "".join(a.split()).lower().encode())
    return ok


# ---------------------------------------------------------------- CLI body

def _agent_uids(prefix: str) -> list[int]:
    try:
        with open(os.path.join(prefix, "spellbook.json")) as f:
            cfg = json.load(f)
    except (OSError, ValueError):
        return []
    uids = cfg.get("allowed_request_uids") or []
    return [u for u in uids if isinstance(u, int)]


def _load_material(prefix: str):
    seed_path = os.path.join(prefix, "seed.key")
    std_entropy_path = os.path.join(prefix, "std_entropy.key")
    std_seed_path = os.path.join(prefix, "std_seed.key")
    kdf_seed = load_seed(seed_path) if os.path.exists(seed_path) else None
    std_entropy = (load_seed(std_entropy_path)
                   if os.path.exists(std_entropy_path) else None)
    std_words_lost = std_entropy is None and os.path.exists(std_seed_path)
    return kdf_seed, std_entropy, std_words_lost


def run_export(prefix: str, *, reveal_key: str | None = None,
               tty_path: str = "/dev/tty", verify: bool = True) -> int:
    """The CLI body. Returns the exit status; reasons go to stderr."""
    if reveal_key is None:
        reason = export_guard(sys.stdin.isatty(), sys.stdout.isatty(),
                              login_uid(), _agent_uids(prefix))
        if reason:
            print(f"spellbook export: refused — {reason}", file=sys.stderr)
            return EXIT_REFUSED
    try:
        kdf_seed, std_entropy, std_words_lost = _load_material(prefix)
        text = paper_backup_text(kdf_seed, std_entropy,
                                 std_words_lost=std_words_lost,
                                 terminal=reveal_key is None)
    except PermissionError:
        print("spellbook export: cannot read the seed files — run it as root "
              "or the spellbook user (e.g. `sudo spellbook export`)",
              file=sys.stderr)
        return 2
    except ValueError as e:
        print(f"spellbook export: {e}", file=sys.stderr)
        return 2

    if reveal_key is not None:
        try:
            envelope = seal_to_reveal_key(text, reveal_key)
        except ValueError as e:
            print(f"spellbook export: {e}", file=sys.stderr)
            return 2
        # Ciphertext only: the page that made the reveal key decrypts it.
        print(envelope)
        return 0

    # The words go to the terminal device itself, never to stdout.
    with open(tty_path, "w") as tty_out, open(tty_path) as tty_in:
        tty_out.write("\n" + text)
        tty_out.flush()
        tty_in.readline()
        tty_out.write(CLEAR_SEQUENCE)
        tty_out.flush()
        if shutil.which("tput"):
            subprocess.run(["tput", "clear"], check=False, stdout=tty_out)
        verified = None
        if verify and std_entropy is not None:
            verified = _verify_on_tty(mnemonic_from_entropy(std_entropy),
                                      tty_in, tty_out)
            # The typed words echoed; clear them too.
            tty_out.write(CLEAR_SEQUENCE)
            tty_out.flush()
    if verified is False:
        print("spellbook export: SET 1 NOT verified after "
              f"{VERIFY_ATTEMPTS} attempts. Run `spellbook export` again "
              "and recopy it.", file=sys.stderr)
        return EXIT_NOT_VERIFIED
    print("spellbook export: paper backup shown once and cleared"
          + (" — SET 1 verified." if verified else "."))
    return 0


def _verify_on_tty(mnemonic: str, tty_in, tty_out) -> bool:
    """Ask for 3 SET 1 words from the paper copy (never echoing the answer)."""
    positions = verification_positions()
    tty_out.write("\nBACKUP VERIFICATION — enter the requested SET 1 words from "
                  "your PAPER copy (the screen above is cleared).\n")
    for attempt in range(1, VERIFY_ATTEMPTS + 1):
        answers = []
        for p in positions:
            tty_out.write(f"Word #{p} of SET 1: ")
            tty_out.flush()
            answers.append(tty_in.readline().strip())
        if check_words(mnemonic, positions, answers):
            tty_out.write("Backup verified. Two copies, two places.\n")
            tty_out.flush()
            return True
        tty_out.write(f"Words do not match (attempt {attempt} of "
                      f"{VERIFY_ATTEMPTS}).\n")
        tty_out.flush()
    return False
