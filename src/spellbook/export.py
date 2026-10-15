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

  envelope  (`spellbook export --reveal-key <b64 SPKI>`) — for the hosted
            backup page (https://spellbook.awizard.dev/ceremony/backup.html,
            web/public/ceremony/backup.js; review S-17), where the human can
            only reach the agent. The page makes a non-extractable RSA
            reveal key in the human's browser and hands the agent the
            PUBLIC half; this
            command encrypts the backup to it and prints only the envelope
            the page decrypts. The agent relays ciphertext and never sees a
            word. It must run with read access to the seed files (root or
            the spellbook user); it prints nothing secret, so it needs no
            terminal.

Forced backup (review S-16): an install is backup-pending, and the
daemon refuses fund-moving routes, until the human proves the backup. The
terminal mode records that proof itself once the typed-back words match
the LIVE seed (3 words when the words are on this machine; all 24 when
only the seed is, after a restore or the passwordless ceremony). The
envelope mode puts a one-time confirmation code inside the encrypted
backup; `spellbook backup-confirm` takes it back (stdin, never argv). Both
write <prefix>/backup.json as root or the daemon user; no daemon route can.

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
from spellbook.seed import entropy_from_mnemonic, load_seed, mnemonic_from_entropy

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
    from spellbook.stdkeys import mnemonic_to_seed
    return _std_addresses_of_seed(mnemonic_to_seed(mnemonic_from_entropy(std_entropy)))


def _std_addresses_of_seed(seed64: bytes) -> dict:
    from spellbook import chia_sign, stdkeys
    from spellbook import solana as solana_mod
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
                      terminal: bool = True,
                      live_std_seed: bytes | None = None,
                      confirm_code: str | None = None,
                      ceremony_fingerprint: str | None = None) -> str:
    """The paper backup: words and addresses, never raw keys."""
    if kdf_seed is None and std_entropy is None and live_std_seed is None:
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
            "copy made at install holds them. Seal the seed (the hosted",
            "seal page) so a wipe never depends on them.",
        ]
    elif live_std_seed is not None:
        # Passwordless ceremony: the human typed these words into the page;
        # only the sealed seed is here, and words cannot be re-derived.
        lines += [
            "",
            "SET 1 — STANDARD RECOVERY: the 24 words you entered on the",
            "ceremony page. This install holds only the sealed seed, so the",
            "words are not shown. Your paper copy must derive these:",
        ]
        if with_addresses:
            a = _std_addresses_of_seed(live_std_seed)
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
              "wallet shows."]
    if ceremony_fingerprint is not None and terminal:
        # Out of band for the human (S-16/S-17): only this terminal
        # shows it; the hosted ceremony pages ask for its first hex
        # digits so an agent-swapped key is caught.
        lines += [
            "",
            "DAEMON CEREMONY KEY FINGERPRINT (sha256, public — not a secret):",
            "  " + ceremony_fingerprint,
            "A sealing page must show this same fingerprint before you seal",
            "or restore anything to it. Note at least the first 16 digits.",
        ]
    if confirm_code is not None:
        lines += [
            "",
            "BACKUP CONFIRMATION CODE:  " + confirm_code,
            "When everything above is on paper, two copies, give this code",
            "to your agent (or run `sudo spellbook backup-confirm`). Until",
            "then the wallet refuses to move funds. The code only confirms",
            "your backup; it cannot open the wallet. One use, 7 days.",
        ]
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

    Format (web/public/ceremony/backup.js, step 2): base64 of JSON
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


def _live(prefix: str):
    """(seed, kind) the daemon signs with, or (None, None) when unreadable."""
    from spellbook import custody
    try:
        return custody.live_seed(prefix)
    except (OSError, ValueError, custody.CustodyError):
        return None, None


def _ceremony_fp(prefix: str) -> str | None:
    from spellbook import custody
    info = custody.public_key_info(prefix)
    return custody.grouped(info["fingerprint"]) if info else None


def run_export(prefix: str, *, reveal_key: str | None = None,
               tty_path: str = "/dev/tty", verify: bool = True) -> int:
    """The CLI body. Returns the exit status; reasons go to stderr."""
    from spellbook import custody
    if reveal_key is None:
        reason = export_guard(sys.stdin.isatty(), sys.stdout.isatty(),
                              login_uid(), _agent_uids(prefix))
        if reason:
            print(f"spellbook export: refused — {reason}", file=sys.stderr)
            return EXIT_REFUSED
    try:
        kdf_seed, std_entropy, std_words_lost = _load_material(prefix)
        live, kind = _live(prefix)
        live_std = (live if kind == "standard" and std_entropy is None
                    and not std_words_lost else None)
        code = None
        if reveal_key is not None:
            # Validate the key before issuing a code for it.
            _load_reveal_key(reveal_key)
            if live is not None:
                code = custody.issue_backup_code(
                    prefix, custody.seed_fingerprint(live))
        text = paper_backup_text(kdf_seed, std_entropy,
                                 std_words_lost=std_words_lost,
                                 terminal=reveal_key is None,
                                 live_std_seed=live_std,
                                 confirm_code=code,
                                 ceremony_fingerprint=_ceremony_fp(prefix))
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

    # What the human proves: the words of the LIVE seed. 3 of them when the
    # words are on this machine; all 24 when only the seed is.
    label, mnemonic = None, None
    if kind == "standard" and std_entropy is not None:
        label, mnemonic = "SET 1", mnemonic_from_entropy(std_entropy)
    elif kind == "kdf" and kdf_seed is not None:
        label, mnemonic = "SET 2", mnemonic_from_entropy(kdf_seed)
    elif kind == "standard" and live is not None:
        label = "SET 1"
    elif std_entropy is not None:
        label, mnemonic = "SET 1", mnemonic_from_entropy(std_entropy)

    # The words go to the terminal device itself, never to stdout.
    verified = None
    with open(tty_path, "w") as tty_out, open(tty_path) as tty_in:
        tty_out.write("\n" + text)
        tty_out.flush()
        tty_in.readline()
        tty_out.write(CLEAR_SEQUENCE)
        tty_out.flush()
        if shutil.which("tput"):
            subprocess.run(["tput", "clear"], check=False, stdout=tty_out)
        if verify and label is not None:
            if mnemonic is not None:
                verified = _verify_on_tty(mnemonic, tty_in, tty_out, label)
            else:
                verified = _verify_reentry(live, tty_in, tty_out, label)
            # The typed words echoed; clear them too.
            tty_out.write(CLEAR_SEQUENCE)
            tty_out.flush()
    if verified is False:
        print(f"spellbook export: {label} NOT verified after "
              f"{VERIFY_ATTEMPTS} attempts. Run `spellbook export` again "
              "and recopy it.", file=sys.stderr)
        return EXIT_NOT_VERIFIED
    recorded = ""
    if verified:
        recorded = _record_confirmation(prefix, live, mnemonic, kind)
    print("spellbook export: paper backup shown once and cleared"
          + (f" — {label} verified." if verified else ".") + recorded)
    return 0


def _record_confirmation(prefix: str, live: bytes | None,
                         mnemonic: str | None, kind: str | None) -> str:
    """Write the backup confirmation for the live seed (S-16), only when the
    verified words are the live seed's own."""
    from spellbook import custody, stdkeys
    if live is None:
        print("spellbook export: the live seed could not be read, so the "
              "backup confirmation was NOT recorded", file=sys.stderr)
        return ""
    if mnemonic is not None:
        derived = (stdkeys.mnemonic_to_seed(mnemonic) if kind == "standard"
                   else entropy_from_mnemonic(mnemonic))
        if not secrets.compare_digest(derived, live):
            print("spellbook export: the verified words are not the live "
                  "wallet's, so the backup confirmation was NOT recorded",
                  file=sys.stderr)
            return ""
    try:
        custody.confirm_backup(prefix, custody.seed_fingerprint(live),
                               "terminal-words")
    except OSError as e:
        print(f"spellbook export: could not record the backup confirmation: "
              f"{type(e).__name__}", file=sys.stderr)
        return ""
    return " Backup confirmed: fund-moving routes are open."


def run_backup_confirm(prefix: str, code: str) -> int:
    """`spellbook backup-confirm`: the reveal-key path's one-time code."""
    from spellbook import custody
    live, _ = _live(prefix)
    if live is None:
        print("spellbook backup-confirm: cannot read the live seed — run it "
              "as root or the spellbook user", file=sys.stderr)
        return 2
    try:
        ok, msg = custody.confirm_with_code(
            prefix, code, custody.seed_fingerprint(live))
    except OSError as e:
        print(f"spellbook backup-confirm: {type(e).__name__}", file=sys.stderr)
        return 2
    if not ok:
        print(f"spellbook backup-confirm: {msg}", file=sys.stderr)
        return EXIT_NOT_VERIFIED
    print("spellbook backup-confirm: backup confirmed; fund-moving routes "
          "are open.")
    return 0


def _verify_reentry(live: bytes, tty_in, tty_out, label: str) -> bool:
    """All 24 words, typed from the paper copy, must give the live seed."""
    from spellbook import stdkeys
    tty_out.write(f"\nBACKUP VERIFICATION — this install keeps no words, only "
                  f"the seed. Enter all 24 {label} words from your PAPER copy "
                  "(the screen above is cleared).\n")
    for attempt in range(1, VERIFY_ATTEMPTS + 1):
        words = []
        for p in range(1, 25):
            tty_out.write(f"Word #{p} of {label}: ")
            tty_out.flush()
            words.append("".join(tty_in.readline().split()).lower())
        try:
            ok = secrets.compare_digest(
                stdkeys.mnemonic_to_seed(" ".join(words)), live)
        except ValueError:
            ok = False
        if ok:
            tty_out.write("Backup verified. Two copies, two places.\n")
            tty_out.flush()
            return True
        tty_out.write(f"Words do not match (attempt {attempt} of "
                      f"{VERIFY_ATTEMPTS}).\n")
        tty_out.flush()
    return False


def _verify_on_tty(mnemonic: str, tty_in, tty_out, label: str = "SET 1") -> bool:
    """Ask for 3 words of `label` from the paper copy (cleared afterwards)."""
    positions = verification_positions()
    tty_out.write(f"\nBACKUP VERIFICATION — enter the requested {label} words "
                  "from your PAPER copy (the screen above is cleared).\n")
    for attempt in range(1, VERIFY_ATTEMPTS + 1):
        answers = []
        for p in positions:
            tty_out.write(f"Word #{p} of {label}: ")
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
