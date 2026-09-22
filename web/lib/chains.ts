// Shared chain config for the /dashboard read-only holdings view.
//
// These are the operator's public testnet drill addresses — public chain
// data, nothing secret. No key material, mnemonics, or tokens live here
// (or anywhere in web/). The Chia relay bearer token is server-only
// (see web/app/api/holdings/route.ts) and comes from Vercel env vars.

export type ChainKind = "evm" | "solana" | "chia";

export interface ChainConfig {
  /** stable id used by the dashboard + holdings API */
  id: string;
  /** display name */
  label: string;
  kind: ChainKind;
  chainId?: number;
  rpcUrl?: string;
  address: string;
  unit: string;
  decimals: number;
  /** sub-detail line shown in the Networks tab, e.g. "EVM · Chain 46630 · Testnet" */
  detail: string;
  /** network color dot (hex) */
  color: string;
}

/** Same key funds the Robinhood testnet wallet; Base/ETH Sepolia read 0 until funded. */
export const EVM_ADDRESS = "0x4c5cbc8fa2cde3511259aee30c0e5d02e34fdc81";

export const SOLANA_ADDRESS = "8cdEnmGF12sgroY9gR81nw46pxjBE3qH7wRvACjWWxHA";

export const CHIA_ADDRESS =
  "txch1jpkhw8e3zap3ccgg6mna26xmz6qlsmq0fsjaxw7zu0fr0574fygsalznn4";

/* ------------------------------------------------------------------ */
/* bech32m decoding — derives any agent's Chia puzzle hash from their  */
/* address, so per-agent sessions don't need a precomputed constant.   */
/* ------------------------------------------------------------------ */

const BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32M_CONST = 0x2bc830a3;

function bech32Polymod(values: number[]): number {
  const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;
  for (const v of values) {
    const b = chk >> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) if ((b >> i) & 1) chk ^= GEN[i];
  }
  return chk;
}

function bech32HrpExpand(hrp: string): number[] {
  const out: number[] = [];
  for (let i = 0; i < hrp.length; i++) out.push(hrp.charCodeAt(i) >> 5);
  out.push(0);
  for (let i = 0; i < hrp.length; i++) out.push(hrp.charCodeAt(i) & 31);
  return out;
}

function convertBits(
  data: number[],
  from: number,
  to: number,
  pad: boolean
): number[] | null {
  let acc = 0;
  let bits = 0;
  const out: number[] = [];
  const maxv = (1 << to) - 1;
  for (const value of data) {
    if (value < 0 || value >> from !== 0) return null;
    acc = (acc << from) | value;
    bits += from;
    while (bits >= to) {
      bits -= to;
      out.push((acc >> bits) & maxv);
    }
  }
  if (pad) {
    if (bits > 0) out.push((acc << (to - bits)) & maxv);
  } else if (bits >= from || ((acc << (to - bits)) & maxv) !== 0) {
    return null;
  }
  return out;
}

/**
 * Decode a Chia bech32m address (txch1… / xch1…) to its 32-byte puzzle
 * hash as 64 hex chars. Null when the address is malformed. Pure
 * function, no secrets — safe to use client-side too.
 */
export function chiaAddressToPuzzleHash(address: string): string | null {
  const addr = address.toLowerCase();
  const pos = addr.lastIndexOf("1");
  if (pos < 1 || pos + 7 > addr.length || addr.length > 90) return null;
  const hrp = addr.slice(0, pos);
  if (hrp !== "txch" && hrp !== "xch") return null;
  const data: number[] = [];
  for (let i = pos + 1; i < addr.length; i++) {
    const d = BECH32_CHARSET.indexOf(addr[i]);
    if (d === -1) return null;
    data.push(d);
  }
  const check = bech32Polymod([...bech32HrpExpand(hrp), ...data]);
  if (check !== BECH32M_CONST) return null;
  const decoded = convertBits(data.slice(0, -6), 5, 8, false);
  if (!decoded || decoded.length !== 32) return null;
  return decoded
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export const CHAINS: ChainConfig[] = [
  {
    id: "robinhood",
    label: "Robinhood Chain",
    kind: "evm",
    chainId: 46630,
    rpcUrl: "https://rpc.testnet.chain.robinhood.com",
    address: EVM_ADDRESS,
    unit: "ETH",
    decimals: 18,
    detail: "EVM · Chain 46630 · Testnet",
    color: "#34d399",
  },
  {
    id: "base-sepolia",
    label: "Base",
    kind: "evm",
    chainId: 84532,
    rpcUrl: "https://sepolia.base.org",
    address: EVM_ADDRESS,
    unit: "ETH",
    decimals: 18,
    detail: "EVM · Base Sepolia · Chain 84532",
    color: "#60a5fa",
  },
  {
    id: "eth-sepolia",
    label: "Ethereum L1",
    kind: "evm",
    chainId: 11155111,
    rpcUrl: "https://ethereum-sepolia-rpc.publicnode.com",
    address: EVM_ADDRESS,
    unit: "ETH",
    decimals: 18,
    detail: "EVM · ETH Sepolia · Chain 11155111",
    color: "#a78bfa",
  },
  {
    id: "solana",
    label: "Solana",
    kind: "solana",
    rpcUrl: "https://api.devnet.solana.com",
    address: SOLANA_ADDRESS,
    unit: "SOL",
    decimals: 9,
    detail: "Devnet",
    color: "#22d3ee",
  },
  {
    id: "chia",
    label: "Chia",
    kind: "chia",
    address: CHIA_ADDRESS,
    unit: "XCH",
    decimals: 12,
    detail: "Testnet11",
    color: "#ff9d5c",
  },
];

export function chainById(id: string): ChainConfig | undefined {
  return CHAINS.find((c) => c.id === id);
}
