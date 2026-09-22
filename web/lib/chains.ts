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

/** Puzzle hash of CHIA_ADDRESS (index-0 testnet wallet), for POST /v1/coins. */
export const CHIA_PUZZLE_HASH =
  "906d771f3117431c6108d6e7d568db1681f86c0f4c25d33bc2e3d237d3d54911";

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
