# Spellbook KDF test vectors

Implements **SPEC_V1.md §2**. Two independent implementations must agree
before any real key is derived — they do (see below).

## Files

| File | What |
|---|---|
| `vectors.json` | The canonical vector file (RFC 8785: sorted keys, no whitespace, `\n`-terminated). SHA-256 over these exact bytes is printed in the spec (P3). |
| `generate.mjs` | Implementation #1: Node, `@noble/hashes` + `@noble/secp256k1` + `@noble/bls12-381`. `node generate.mjs` regenerates `vectors.json` and prints its SHA-256. |
| `verify.py` | Implementation #2: Python. Hand-rolled RFC 5869 HKDF (stdlib), pure-Python secp256k1, keccak via pycryptodome, BLS12-381 G1 via py_ecc, real BIP-39 checksum validation against `bip39-english.txt`. `python3 verify.py` — exit 0 means green. |
| `bip39-english.txt` | BIP-39 English wordlist (source: bitcoin/bips, bip-0039). Test tooling only. |
| `package.json`, `node_modules/` | Node deps for the generator. |

## What's covered

- **Positive:** `evm-4663`/`evm-46630`/`tips` labels (EVM address = keccak256 of the 64-byte *uncompressed* key, S5), `chia-mainnet`/`chia-testnet` (48-byte BLS master pubkey; Chia *addresses* are asserted in the Sage drill, §10 step 10 — a Chia address is not a pure function of the master key, P3).
- **P9 invariant:** `evm-4663` and `evm-46630` derive *different* keys — asserted by a dedicated vector pair and re-checked by `verify.py`. Never fund a testnet-derived address on mainnet.
- **Resampling (S12, Nimbus):** `chia-mainnet-sign-resample-demo` uses a seed whose first HKDF expansion is ≥ the BLS12-381 order and was rejected; the key comes from `/ctr/1`. Never reduce mod the order.
- **Negative:** short seed, scalar == secp256k1 order, zero scalar, bad BIP-39 checksum — each carries its expected failure.

## Test seed

`000102…1f` — obviously synthetic, never a real key. All vectors are
reproducible from it; no secrets anywhere in this directory.

## Status

- [x] Implementation #1 (Node/noble) generates the file
- [x] Implementation #2 (Python) reproduces every vector independently
- [ ] Daemon (implementation #3) reproduces them at build time (§10 step 2)
