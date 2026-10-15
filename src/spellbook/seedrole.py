"""Seed role — is the daemon's KDF seed a Musebook identity seed? (S1 / S-04)

Under `key_derivation=kdf` the 32-byte seed at `seed_path` is the HKDF
input for every EVM, Chia and Solana key. When that same seed is also the
muse's Ed25519 identity seed, whoever holds the identity seed derives every
wallet key offline and the daemon's policy, queue and ledger are bypassed.
The S1 decision (a separate daemon-generated wallet root, "Option B") is
still open; until it lands the daemon refuses to START in that shape unless
the operator explicitly opts in with `allow_identity_seed_as_wallet_root`.

Everything here is a pure function over the config dict and the seed file's
text, so it is testable without a daemon, a socket or a real seed.

Markers that say "this seed is an identity seed" (any one is enough):

  - config `seed_role` is "identity";
  - config `musebook_signing_mode` is "daemon" — the daemon is configured
    to sign the muse's identity with this seed, so it IS the identity seed;
  - the seed file carries the role header line (see IDENTITY_ROLE_HEADER);
  - the seed file path names the Musebook client (`musebook` anywhere in
    the path), is a `.env` file, or names the agent's dashboard identity
    key file (`agent_ed25519`) — the places a muse's identity seed
    actually lives today.

Sealed seeds (sealed.py) are covered: `spellbook-seed unlock` writes the
seed back to the same `seed_path`, and the role header is carried inside
the sealed plaintext and rewritten on unlock, so a labelled identity seed
stays labelled across a wipe. The passwordless ENC2 envelope only ever
carries the 64-byte standard seed (key_derivation=standard), which is not
the KDF root and so is outside this check.

An explicit `seed_role: "wallet"` does NOT silence the other markers: a
seed cannot be both, and a wallet root that signs Musebook identity is the
exact shape S-04 is about. The contradiction is refused instead.
"""
import os

SEED_ROLES = ("identity", "wallet")

# A comment line a muse puts at the top of seed.key to label it. load_seed()
# tolerates `#` comment lines, so the label costs nothing at load time.
IDENTITY_ROLE_HEADER = "# spellbook-seed-role: identity"
WALLET_ROLE_HEADER = "# spellbook-seed-role: wallet"

ALLOW_KEY = "allow_identity_seed_as_wallet_root"


class IdentitySeedAsWalletRoot(RuntimeError):
    """The daemon's wallet root is a Musebook identity seed (S1 open)."""


def seed_file_role(text: str) -> str | None:
    """Role declared by the seed file's own header lines, or None.

    `text` is the raw file content. Only `#` comment lines are read; the
    hex payload is never inspected or returned.
    """
    for line in text.splitlines():
        s = line.strip()
        if not s.startswith("#"):
            continue
        if s == IDENTITY_ROLE_HEADER:
            return "identity"
        if s == WALLET_ROLE_HEADER:
            return "wallet"
    return None


def seed_path_markers(seed_path: str | None) -> list[str]:
    """Markers carried by the seed file's PATH (no file access)."""
    if not seed_path:
        return []
    out = []
    norm = seed_path.replace("\\", "/").lower()
    base = os.path.basename(norm)
    if "musebook" in norm:
        out.append("seed_path names the Musebook client")
    if base == ".env" or base.endswith(".env"):
        out.append("seed_path is a .env file")
    if "agent_ed25519" in base:
        out.append("seed_path names the agent's dashboard identity key")
    return out


def identity_seed_markers(cfg: dict, seed_file_text: str | None = None) -> list[str]:
    """Every reason to believe `seed_path` holds a Musebook identity seed.

    `seed_file_text` is the seed file's content when the caller has it
    (the daemon has, after load); None means "not inspected".
    """
    out = []
    role = cfg.get("seed_role")
    if role is not None and role not in SEED_ROLES:
        raise ValueError("seed_role must be 'identity' or 'wallet'")
    if role == "identity":
        out.append("config seed_role=identity")
    if cfg.get("musebook_signing_mode") == "daemon":
        out.append("config musebook_signing_mode=daemon (the seed signs the muse's identity)")
    if seed_file_text is not None and seed_file_role(seed_file_text) == "identity":
        out.append("seed file header declares role identity")
    out.extend(seed_path_markers(cfg.get("seed_path")))
    return out


def check_wallet_root(cfg: dict, seed_file_text: str | None = None) -> list[str]:
    """Refuse the S-04 configuration; return the markers found (maybe empty).

    Raises IdentitySeedAsWalletRoot when `key_derivation` is "kdf" (the
    default), a seed is configured, at least one identity marker is present
    and `allow_identity_seed_as_wallet_root` is not exactly True. Under
    `key_derivation=standard` the KDF seed is not the wallet root (the
    BIP-39 std seed is), so the same seed may serve as identity there —
    that is the Option B shape.
    """
    allow = cfg.get(ALLOW_KEY, False)
    if allow is not False and allow is not True:
        raise ValueError(f"{ALLOW_KEY} must be true or false")
    if not cfg.get("seed_path"):
        return []
    markers = identity_seed_markers(cfg, seed_file_text)
    if cfg.get("seed_role") == "wallet" and markers:
        raise IdentitySeedAsWalletRoot(
            "seed_role=wallet contradicts: " + "; ".join(markers)
            + ". A seed cannot be both the wallet root and the Musebook "
            "identity seed (S1).")
    if cfg.get("key_derivation", "kdf") != "kdf":
        return markers
    if markers and not allow:
        raise IdentitySeedAsWalletRoot(
            "refusing to start: under key_derivation=kdf the seed at seed_path "
            "is the wallet root for every chain, and it looks like a Musebook "
            "identity seed (" + "; ".join(markers) + "). Whoever holds the "
            "identity seed would hold every wallet key offline, bypassing this "
            "daemon (S1, still open; review S-04). Fix: give the daemon its own "
            "wallet root (key_derivation=standard with std_seed_path, or a "
            "freshly generated seed.key), or set "
            f"{ALLOW_KEY}=true to accept this knowingly (unsafe).")
    return markers
