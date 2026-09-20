#!/usr/bin/env node
/**
 * Spellbook KDF test-vector generator — implementation #1 (Node, @noble/*).
 *
 * Implements SPEC_V1.md §2 exactly:
 *   scalar_bytes = HKDF-SHA256(IKM=seed32, salt="muse-wallet-v1",
 *                              info="muse-wallet/v1/<chain>/sign/<label>", L=32)
 *   scalar = int_be(scalar_bytes); if scalar == 0 or scalar >= curve_order:
 *       re-expand with info + "/ctr/1", "/ctr/2", ... (never reduce mod order)
 *   EVM: scalar -> secp256k1 -> uncompressed 64-byte pubkey ->
 *        address = last 20 bytes of keccak256(pubkey)
 *   Chia: scalar -> BLS12-381 secret -> 48-byte G1 pubkey
 *        (address derivation happens in Sage per the drill; see README)
 *
 * Writes vectors/vectors.json in canonical form (RFC 8785: sorted keys,
 * no whitespace) and prints the SHA-256 over the file bytes. That hash is
 * printed into SPEC_V1.md per P3.
 *
 * Usage: node generate.mjs [--out vectors.json]
 */
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { getPublicKey as secpPubkey, Point as SecpPoint } from '@noble/secp256k1';
import { getPublicKey as blsPubkey, CURVE as blsCURVE } from '@noble/bls12-381';
import { writeFileSync } from 'node:fs';

const SALT = 'muse-wallet-v1';
const SECP_N = SecpPoint.CURVE().n;
const BLS_R = blsCURVE.r;

// Obviously-synthetic test seed: bytes 0x00..0x1f. NEVER a real key.
const TEST_SEED = Uint8Array.from({ length: 32 }, (_, i) => i);

const hex = (b) => Buffer.from(b).toString('hex');
const intBe = (b) => BigInt('0x' + (hex(b) || '00'));

function deriveScalar(seed, info, order) {
  if (seed.length !== 32) throw new Error('seed must be exactly 32 bytes');
  let ctr = 0;
  for (;;) {
    const infoBytes = new TextEncoder().encode(ctr === 0 ? info : `${info}/ctr/${ctr}`);
    const okm = hkdf(sha256, seed, new TextEncoder().encode(SALT), infoBytes, 32);
    const v = intBe(okm);
    if (v !== 0n && v < order) return { scalarHex: hex(okm), ctr };
    ctr++;
    if (ctr > 1000) throw new Error('resample loop exceeded 1000 tries');
  }
}

function evmVector(vector_id, seed, chain, label) {
  const info = `muse-wallet/v1/${chain}/sign/${label}`;
  const { scalarHex, ctr } = deriveScalar(seed, info, SECP_N);
  const pub = secpPubkey(hexToBytes(scalarHex), false); // 65 bytes, 0x04 || x || y
  const uncompressed = pub.slice(1);                    // 64 bytes, per spec (S5)
  const addr = '0x' + hex(keccak_256(uncompressed)).slice(-40);
  return {
    vector_id, test_seed_hex: hex(seed), domain_tag: info, chain, label,
    resampled: ctr > 0, ctr_used: ctr,
    expected_scalar_hex: scalarHex,
    expected_pubkey_hex: hex(uncompressed), // 64-byte uncompressed, no 0x04 prefix
    expected_address: addr,
  };
}

function chiaVector(vector_id, seed, chain, label, note) {
  const info = `muse-wallet/v1/${chain}/sign/${label}`;
  const { scalarHex, ctr } = deriveScalar(seed, info, BLS_R);
  const pub = blsPubkey(hexToBytes(scalarHex)); // 48-byte G1
  const v = { vector_id, test_seed_hex: hex(seed), domain_tag: info, chain, label,
    resampled: ctr > 0, ctr_used: ctr,
    expected_scalar_hex: scalarHex,
    expected_master_pubkey_hex: hex(pub),
  };
  if (note) v.note = note;
  return v;
}

function hexToBytes(h) { return Uint8Array.from(Buffer.from(h, 'hex')); }

// --- find a seed whose FIRST BLS expansion is rejected but /ctr/1 is accepted ---
// A clean two-step demo of the reject-and-resample rule (S12).
function findResampleSeed() {
  for (let b = 0; b < 256; b++) {
    const seed = Uint8Array.from(TEST_SEED);
    seed[31] = b;
    const info = 'muse-wallet/v1/chia-mainnet/sign/default';
    const first = hkdf(sha256, seed, new TextEncoder().encode(SALT), new TextEncoder().encode(info), 32);
    const second = hkdf(sha256, seed, new TextEncoder().encode(SALT), new TextEncoder().encode(info + '/ctr/1'), 32);
    if (intBe(first) >= BLS_R && intBe(second) !== 0n && intBe(second) < BLS_R) return seed;
  }
  throw new Error('no clean resample seed found in 256 tries (unlikely: p ~ 1/4 per seed)');
}

const vectors = [
  evmVector('evm-4663-sign-default', TEST_SEED, 'evm-4663', 'default'),
  evmVector('evm-46630-sign-default', TEST_SEED, 'evm-46630', 'default'),
  evmVector('evm-4663-sign-tips', TEST_SEED, 'evm-4663', 'tips'),
  chiaVector('chia-mainnet-sign-default', TEST_SEED, 'chia-mainnet', 'default'),
  chiaVector('chia-testnet-sign-default', TEST_SEED, 'chia-testnet', 'default'),
  chiaVector('chia-mainnet-sign-resample-demo', findResampleSeed(), 'chia-mainnet', 'default',
    'First HKDF expansion was >= BLS12-381 r and rejected; key comes from /ctr/1. This is the reject-and-resample rule (S12) firing on a real seed.'),
  // --- negative vectors: each carries its expected failure ---
  { vector_id: 'kdf-negative-short-seed',
    test_seed_hex: hex(TEST_SEED.slice(0, 31)),
    expected_failure: 'reject: seed must be exactly 32 bytes' },
  { vector_id: 'kdf-negative-secp256k1-scalar-at-order',
    test_seed_hex: null,
    note: 'Validation-layer vector: scalar bytes equal to the secp256k1 curve order n.',
    scalar_hex: SECP_N.toString(16).padStart(64, '0'),
    expected_failure: 'reject: scalar >= curve order (never reduce mod n)' },
  { vector_id: 'kdf-negative-bls-scalar-zero',
    test_seed_hex: null,
    note: 'Validation-layer vector: 32 zero bytes as the scalar.',
    scalar_hex: '00'.repeat(32),
    expected_failure: 'reject: scalar is zero' },
  { vector_id: 'kdf-negative-bip39-checksum',
    test_seed_hex: null,
    note: 'Static vector: twelve "abandon" words has an invalid BIP-39 checksum (the valid zero-entropy mnemonic ends in "about"). Paper-backup import must refuse it.',
    mnemonic: 'abandon '.repeat(11).trim() + ' abandon',
    expected_failure: 'reject: BIP-39 checksum invalid' },
];

const doc = { spec: 'SPEC_V1.md §2', kdf: 'HKDF-SHA256, salt "muse-wallet-v1", L=32', vectors };

// --- RFC 8785 canonicalization (data is ASCII-only, so code-unit sort is exact) ---
function canon(v) {
  if (v === null || v === undefined) return 'null';
  if (typeof v === 'boolean' || typeof v === 'number') return JSON.stringify(v);
  if (typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
}

const outPath = process.argv.includes('--out') ? process.argv[process.argv.indexOf('--out') + 1] : 'vectors.json';
const bytes = new TextEncoder().encode(canon(doc) + '\n');
writeFileSync(outPath, bytes);
console.log('wrote', outPath);
console.log('sha256:', hex(sha256(bytes)));
console.log('vectors:', vectors.length);
