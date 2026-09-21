/**
 * Chia helpers for the Spellbook first-tester dashboard.
 *
 * - bech32m address decode/encode (Chia uses bech32m for xch1… / txch1…)
 * - input validation (hex, puzzle hashes, spend bundles)
 * - typed client for the spellbook-chia-relay v1 HTTPS API
 *
 * This module NEVER touches seeds, mnemonics, or private keys. If a caller
 * ever passes one here, that is a bug — the dashboard has no key handling.
 */

const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
/** bech32m checksum constant (BIP-0350). */
const BECH32M_CONST = 0x2bc830a3;
const MOJOS_PER_XCH = 1_000_000_000_000;

// ---------------------------------------------------------------------------
// bech32m
// ---------------------------------------------------------------------------

function polymod(values: number[]): number {
  const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;
  for (const v of values) {
    const top = chk >> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) {
      if ((top >> i) & 1) chk ^= GEN[i];
    }
  }
  // >>> 0 keeps it unsigned in JS number land
  return chk >>> 0;
}

function hrpExpand(hrp: string): number[] {
  const ret: number[] = [];
  for (const c of hrp) ret.push(c.charCodeAt(0) >> 5);
  ret.push(0);
  for (const c of hrp) ret.push(c.charCodeAt(0) & 31);
  return ret;
}

function convertBits(
  data: number[],
  from: number,
  to: number,
  pad: boolean
): number[] | null {
  let acc = 0;
  let bits = 0;
  const ret: number[] = [];
  const maxv = (1 << to) - 1;
  for (const value of data) {
    if (value < 0 || value >> from) return null;
    acc = (acc << from) | value;
    bits += from;
    while (bits >= to) {
      bits -= to;
      ret.push((acc >> bits) & maxv);
    }
  }
  if (pad) {
    if (bits > 0) ret.push((acc << (to - bits)) & maxv);
  } else if (bits >= from || ((acc << (to - bits)) & maxv)) {
    return null;
  }
  return ret;
}

function bytesToHex(bytes: number[]): string {
  return bytes.map((b) => b.toString(16).padStart(2, "0")).join("");
}

function hexToBytes(hex: string): number[] | null {
  if (!/^[0-9a-fA-F]*$/.test(hex) || hex.length % 2 !== 0) return null;
  const out: number[] = [];
  for (let i = 0; i < hex.length; i += 2) {
    out.push(parseInt(hex.slice(i, i + 2), 16));
  }
  return out;
}

export interface DecodedAddress {
  hrp: string;
  /** 64-char lowercase hex puzzle hash */
  puzzleHash: string;
}

/**
 * Decode a Chia address (xch1… / txch1…) to its 32-byte puzzle hash.
 * Throws on any malformed input. Only accepts bech32m.
 */
export function decodeAddress(addr: string): DecodedAddress {
  const input = addr.trim();
  if (input.length === 0) throw new Error("empty address");
  if (input.length > 200) throw new Error("address too long");
  const lower = input.toLowerCase();
  const upper = input.toUpperCase();
  if (input !== lower && input !== upper) {
    throw new Error("mixed-case address");
  }
  const a = lower;
  const pos = a.lastIndexOf("1");
  if (pos < 1 || pos + 7 > a.length) throw new Error("bad separator");
  const hrp = a.slice(0, pos);
  if (!/^[a-z0-9]+$/.test(hrp)) throw new Error("bad human-readable part");
  const data: number[] = [];
  for (const c of a.slice(pos + 1)) {
    const v = CHARSET.indexOf(c);
    if (v < 0) throw new Error(`bad bech32 character: ${c}`);
    data.push(v);
  }
  if (polymod([...hrpExpand(hrp), ...data]) !== BECH32M_CONST) {
    throw new Error("bad checksum (not a bech32m address)");
  }
  const payload = convertBits(data.slice(0, -6), 5, 8, false);
  if (!payload || payload.length !== 32) {
    throw new Error("bad payload length (expected 32 bytes)");
  }
  return { hrp, puzzleHash: bytesToHex(payload) };
}

/** Encode a 32-byte puzzle hash hex to a bech32m address (for verification). */
export function encodeAddress(hrp: string, puzzleHashHex: string): string {
  const bytes = hexToBytes(puzzleHashHex);
  if (!bytes || bytes.length !== 32) throw new Error("puzzle hash must be 32 bytes hex");
  const data5 = convertBits(bytes, 8, 5, true);
  if (!data5) throw new Error("convertBits failed");
  const values = [...hrpExpand(hrp), ...data5, 0, 0, 0, 0, 0, 0];
  const mod = (polymod(values) ^ BECH32M_CONST) >>> 0;
  const chk: number[] = [];
  for (let p = 0; p < 6; p++) chk.push((mod >> (5 * (5 - p))) & 31);
  return hrp + "1" + [...data5, ...chk].map((v) => CHARSET[v]).join("");
}

// ---------------------------------------------------------------------------
// validation
// ---------------------------------------------------------------------------

export function isHex(s: string): boolean {
  return /^[0-9a-fA-F]*$/.test(s) && s.length % 2 === 0;
}

/** 64 hex chars = 32 bytes. */
export function isPuzzleHash(s: string): boolean {
  return /^[0-9a-fA-F]{64}$/.test(s);
}

/** Spend bundle hex: non-empty even-length hex, relay caps at 5 MB. */
export function validateSpendBundleHex(s: string): string | null {
  const t = s.trim().replace(/^0x/i, "");
  if (t.length === 0) return "empty bundle";
  if (!isHex(t)) return "not valid hex";
  if (t.length / 2 > 5 * 1024 * 1024) return "bundle exceeds 5 MB relay limit";
  return null;
}

export function formatXch(mojos: number | string): string {
  const m = typeof mojos === "string" ? Number(mojos) : mojos;
  if (!Number.isFinite(m)) return "—";
  const xch = m / MOJOS_PER_XCH;
  // show up to 12 decimals, trim trailing zeros
  return xch.toFixed(12).replace(/\.?0+$/, "") || "0";
}

export function shortHash(hex: string, n = 10): string {
  return hex.length > n * 2 ? `${hex.slice(0, n)}…${hex.slice(-n)}` : hex;
}

// ---------------------------------------------------------------------------
// relay API client
// ---------------------------------------------------------------------------

export interface RelayStatus {
  ok: boolean;
  network: string;
  peak_height: number;
  peers: number;
  watched_addresses: number;
  uptime_s: number;
}

export interface Coin {
  coin_id: string;
  parent_coin_info: string;
  puzzle_hash: string;
  amount_mojos: number;
  created_height: number;
  spent_height: number | null;
}

export interface BroadcastResult {
  ok: boolean;
  txid: string;
  /** MempoolInclusionStatus: 1 = SUCCESS, 2 = PENDING, 3 = FAILED */
  status: number;
  error?: string;
}

export interface CoinState {
  coin_id: string;
  created_height: number;
  spent_height: number | null;
}

export class RelayError extends Error {
  constructor(
    message: string,
    public readonly status?: number
  ) {
    super(message);
    this.name = "RelayError";
  }
}

export class RelayClient {
  constructor(
    private baseUrl: string,
    private token: string
  ) {}

  private async req<T>(path: string, init?: RequestInit): Promise<T> {
    const url = this.baseUrl.replace(/\/+$/, "") + path;
    let res: Response;
    try {
      res = await fetch(url, {
        ...init,
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${this.token}`,
          ...(init?.headers ?? {}),
        },
      });
    } catch (e) {
      throw new RelayError(
        `network error reaching relay: ${e instanceof Error ? e.message : String(e)}`
      );
    }
    let body: unknown = null;
    try {
      body = await res.json();
    } catch {
      // non-JSON body
    }
    if (!res.ok) {
      const msg =
        body && typeof body === "object" && "error" in body
          ? String((body as { error: unknown }).error)
          : `HTTP ${res.status}`;
      throw new RelayError(msg, res.status);
    }
    return body as T;
  }

  status(): Promise<RelayStatus> {
    return this.req<RelayStatus>("/v1/status");
  }

  async coins(puzzleHashes: string[]): Promise<Coin[]> {
    if (puzzleHashes.length === 0) return [];
    if (puzzleHashes.length > 50) {
      throw new RelayError("too many puzzle hashes (max 50)");
    }
    for (const h of puzzleHashes) {
      if (!isPuzzleHash(h)) throw new RelayError(`bad puzzle hash: ${h.slice(0, 16)}…`);
    }
    const r = await this.req<{ coins: Coin[] }>("/v1/coins", {
      method: "POST",
      body: JSON.stringify({ puzzle_hashes: puzzleHashes.map((h) => h.toLowerCase()) }),
    });
    if (!r || !Array.isArray(r.coins)) throw new RelayError("malformed /v1/coins response");
    return r.coins;
  }

  async broadcast(spendBundleHex: string): Promise<BroadcastResult> {
    const err = validateSpendBundleHex(spendBundleHex);
    if (err) throw new RelayError(err);
    const r = await this.req<BroadcastResult>("/v1/broadcast", {
      method: "POST",
      body: JSON.stringify({
        spend_bundle_hex: spendBundleHex.trim().replace(/^0x/i, "").toLowerCase(),
      }),
    });
    if (!r || typeof r.ok !== "boolean") throw new RelayError("malformed /v1/broadcast response");
    return r;
  }

  coin(coinId: string): Promise<CoinState> {
    if (!isPuzzleHash(coinId)) throw new RelayError("bad coin id");
    return this.req<CoinState>(`/v1/coin/${coinId.toLowerCase()}`);
  }
}

export function mempoolStatusLabel(status: number): string {
  switch (status) {
    case 1:
      return "SUCCESS — in mempool";
    case 2:
      return "PENDING — mempool review";
    case 3:
      return "FAILED — rejected";
    default:
      return `unknown (${status})`;
  }
}
