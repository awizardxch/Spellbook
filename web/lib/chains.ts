// Shared chain config for the /dashboard read-only holdings view.
//
// Mainnet is live: every network is listed as a mainnet + testnet pair,
// each side independently toggleable. These are public chain reads — no
// key material, mnemonics, or tokens live here (or anywhere in web/).
// The Chia relay bearer token is server-only (see
// web/app/api/holdings/route.ts) and comes from Vercel env vars.
//
// Mainnet and testnet derive DIFFERENT keys (SPEC §2/P9), so agents bind
// their mainnet watch addresses separately at login (see web/lib/auth.ts).
// The drill constants below are the operator's public testnet drill
// addresses; mainnet drill addresses are not configured ("" = the chain
// is skipped in the shared drill view).

export type ChainKind = "evm" | "solana" | "chia";

/** Which side of a network pair this entry is. */
export type ChainEnv = "mainnet" | "testnet";

export interface ChainConfig {
  /** stable id used by the dashboard + holdings API, e.g. "robinhood-mainnet" */
  id: string;
  /** groups a network's mainnet + testnet pair, e.g. "robinhood" */
  networkId: string;
  /** display name of the network, e.g. "Robinhood Chain" */
  networkLabel: string;
  /** mainnet or testnet side of the pair */
  env: ChainEnv;
  kind: ChainKind;
  chainId?: number;
  rpcUrl?: string;
  /**
   * Drill fallback address for the shared operator view. Empty string =
   * not configured: the chain is skipped in drill view (agents and
   * per-agent viewer tokens bind their own addresses at login).
   */
  address: string;
  unit: string;
  decimals: number;
  /** sub-detail line shown in the dashboard, e.g. "EVM · Chain 4663 · Mainnet" */
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
    id: "robinhood-mainnet",
    networkId: "robinhood",
    networkLabel: "Robinhood Chain",
    env: "mainnet",
    kind: "evm",
    chainId: 4663,
    rpcUrl: "https://rpc.mainnet.chain.robinhood.com",
    address: "",
    unit: "ETH",
    decimals: 18,
    detail: "EVM · Chain 4663 · Mainnet",
    color: "#34d399",
  },
  {
    id: "robinhood-testnet",
    networkId: "robinhood",
    networkLabel: "Robinhood Chain",
    env: "testnet",
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
    id: "base-mainnet",
    networkId: "base",
    networkLabel: "Base",
    env: "mainnet",
    kind: "evm",
    chainId: 8453,
    rpcUrl: "https://mainnet.base.org",
    address: "",
    unit: "ETH",
    decimals: 18,
    detail: "EVM · Base · Chain 8453 · Mainnet",
    color: "#60a5fa",
  },
  {
    id: "base-testnet",
    networkId: "base",
    networkLabel: "Base",
    env: "testnet",
    kind: "evm",
    chainId: 84532,
    rpcUrl: "https://sepolia.base.org",
    address: EVM_ADDRESS,
    unit: "ETH",
    decimals: 18,
    detail: "EVM · Base Sepolia · Chain 84532 · Testnet",
    color: "#60a5fa",
  },
  {
    id: "ethereum-mainnet",
    networkId: "ethereum",
    networkLabel: "Ethereum L1",
    env: "mainnet",
    kind: "evm",
    chainId: 1,
    rpcUrl: "https://ethereum-rpc.publicnode.com",
    address: "",
    unit: "ETH",
    decimals: 18,
    detail: "EVM · Ethereum · Chain 1 · Mainnet",
    color: "#a78bfa",
  },
  {
    id: "ethereum-testnet",
    networkId: "ethereum",
    networkLabel: "Ethereum L1",
    env: "testnet",
    kind: "evm",
    chainId: 11155111,
    rpcUrl: "https://ethereum-sepolia-rpc.publicnode.com",
    address: EVM_ADDRESS,
    unit: "ETH",
    decimals: 18,
    detail: "EVM · ETH Sepolia · Chain 11155111 · Testnet",
    color: "#a78bfa",
  },
  {
    id: "solana-mainnet",
    networkId: "solana",
    networkLabel: "Solana",
    env: "mainnet",
    kind: "solana",
    rpcUrl: "https://api.mainnet-beta.solana.com",
    address: "",
    unit: "SOL",
    decimals: 9,
    detail: "Mainnet-beta",
    color: "#22d3ee",
  },
  {
    id: "solana-testnet",
    networkId: "solana",
    networkLabel: "Solana",
    env: "testnet",
    kind: "solana",
    rpcUrl: "https://api.devnet.solana.com",
    address: SOLANA_ADDRESS,
    unit: "SOL",
    decimals: 9,
    detail: "Devnet",
    color: "#22d3ee",
  },
  {
    id: "chia-mainnet",
    networkId: "chia",
    networkLabel: "Chia",
    env: "mainnet",
    kind: "chia",
    address: "",
    unit: "XCH",
    decimals: 12,
    detail: "Mainnet",
    color: "#ff9d5c",
  },
  {
    id: "chia-testnet",
    networkId: "chia",
    networkLabel: "Chia",
    env: "testnet",
    kind: "chia",
    address: CHIA_ADDRESS,
    unit: "XCH",
    decimals: 12,
    detail: "Testnet11",
    color: "#ff9d5c",
  },
];

/** The five networks, each as its [mainnet, testnet] pair, in display order. */
export const NETWORKS: { id: string; label: string; chains: ChainConfig[] }[] =
  (() => {
    const order: string[] = [];
    const byId = new Map<string, ChainConfig[]>();
    for (const c of CHAINS) {
      if (!byId.has(c.networkId)) {
        byId.set(c.networkId, []);
        order.push(c.networkId);
      }
      byId.get(c.networkId)!.push(c);
    }
    return order.map((networkId) => {
      const chains = byId.get(networkId)!;
      return { id: networkId, label: chains[0].networkLabel, chains };
    });
  })();

export function chainById(id: string): ChainConfig | undefined {
  return CHAINS.find((c) => c.id === id);
}
