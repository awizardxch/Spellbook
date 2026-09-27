// Uniswap v4 LP position reads for the Spellbook dashboard.
//
// Read-only Uniswap v4 (Robinhood Chain, chain id 4663) position discovery
// and valuation. Everything here is a public `eth_call` / `eth_getLogs`
// against a public RPC — no signing, no broadcasts, no key material.
//
// Discovery: PositionManager is an ERC721 with no enumeration, so positions
// are found by scanning its Transfer events for the wallet (topic-filtered,
// block-paginated). Pool state (sqrtPriceX96, tick, liquidity) is read via
// StateView.getSlot0 — PoolManager.getSlot0 is NOT used: it reverts on
// Robinhood's modified deployment.
//
// Unclaimed fees use fee-growth accounting:
//   fees = (feeGrowthInside - feeGrowthInsideLast) * liquidity / 2**128
// APR is an honest estimate from trailing swap volume in the pool (see
// estimateApr): the UI must label it as an estimate.

export const V4_POSITION_MANAGER =
  "0x58daec3116aae6d93017baaea7749052e8a04fa7";
export const V4_STATE_VIEW = "0xf3334192d15450cdd385c8b70e03f9a6bd9e673b";
export const V4_POOL_MANAGER = "0x8366a39cc670b4001a1121b8f6a443a643e40951";
export const V4_NATIVE = "0x0000000000000000000000000000000000000000";

/* ------------------------------------------------------------------ */
/* keccak-256 (Ethereum flavor), dependency-free                       */
/* ------------------------------------------------------------------ */

const KECCAK_ROT = [
  0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8,
  18, 2, 61, 56, 14,
];
const KECCAK_RC = [
  BigInt("0x0000000000000001"), BigInt("0x0000000000008082"), BigInt("0x800000000000808a"),
  BigInt("0x8000000080008000"), BigInt("0x000000000000808b"), BigInt("0x0000000080000001"),
  BigInt("0x8000000080008081"), BigInt("0x8000000000008009"), BigInt("0x000000000000008a"),
  BigInt("0x0000000000000088"), BigInt("0x0000000080008009"), BigInt("0x000000008000000a"),
  BigInt("0x000000008000808b"), BigInt("0x800000000000008b"), BigInt("0x8000000000008089"),
  BigInt("0x8000000000008003"), BigInt("0x8000000000008002"), BigInt("0x8000000000000080"),
  BigInt("0x000000000000800a"), BigInt("0x800000008000000a"), BigInt("0x8000000080008081"),
  BigInt("0x8000000000008080"), BigInt("0x0000000080000001"), BigInt("0x8000000080008008"),
];
const MASK64 = (BigInt(1) << BigInt(64)) - BigInt(1);

function keccakF(s: bigint[]): void {
  for (let round = 0; round < 24; round++) {
    const C = new Array<bigint>(5);
    for (let x = 0; x < 5; x++)
      C[x] = s[x] ^ s[x + 5] ^ s[x + 10] ^ s[x + 15] ^ s[x + 20];
    for (let x = 0; x < 5; x++) {
      const d =
        (C[(x + 4) % 5] ^
          ((C[(x + 1) % 5] << BigInt(1)) | (C[(x + 1) % 5] >> BigInt(63)))) &
        MASK64;
      for (let y = 0; y < 5; y++) s[x + 5 * y] ^= d;
    }
    const B = new Array<bigint>(25);
    for (let x = 0; x < 5; x++)
      for (let y = 0; y < 5; y++) {
        const idx = x + 5 * y;
        const r = KECCAK_ROT[idx];
        const v = s[idx];
        B[y + 5 * ((2 * x + 3 * y) % 5)] =
          r === 0
            ? v & MASK64
            : ((v << BigInt(r)) | (v >> BigInt(64 - r))) & MASK64;
      }
    for (let x = 0; x < 5; x++)
      for (let y = 0; y < 5; y++)
        s[x + 5 * y] =
          (B[x + 5 * y] ^
            (~B[((x + 1) % 5) + 5 * y] & B[((x + 2) % 5) + 5 * y])) &
          MASK64;
    s[0] ^= KECCAK_RC[round];
  }
}

/** keccak256 of raw bytes, returned as 0x hex. */
export function keccak256Hex(data: Uint8Array): string {
  const blockSize = 136; // rate for keccak-256
  const s = new Array<bigint>(25).fill(BigInt(0));
  const paddedLen =
    Math.floor((data.length + 1) / blockSize) * blockSize + blockSize;
  const buf = new Uint8Array(paddedLen);
  buf.set(data);
  buf[data.length] = 0x01;
  buf[paddedLen - 1] |= 0x80;
  for (let off = 0; off < paddedLen; off += blockSize) {
    for (let i = 0; i < blockSize / 8; i++) {
      let lane = BigInt(0);
      for (let b = 0; b < 8; b++)
        lane |= BigInt(buf[off + i * 8 + b]) << BigInt(8 * b);
      s[i] ^= lane;
    }
    keccakF(s);
  }
  let out = "0x";
  for (let i = 0; i < 4; i++)
    for (let b = 0; b < 8; b++)
      out += ((s[i] >> BigInt(8 * b)) & BigInt("0xff"))
        .toString(16)
        .padStart(2, "0");
  return out;
}

function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

/** First 4 bytes of keccak(signature) as 8 bare hex chars — a function selector. */
export function selector(sig: string): string {
  return keccak256Hex(utf8(sig)).slice(2, 10);
}

export const TRANSFER_TOPIC = keccak256Hex(
  utf8("Transfer(address,address,uint256)")
);
export const SWAP_TOPIC = keccak256Hex(
  utf8("Swap(bytes32,address,int128,int128,uint160,uint128,int24,uint24)")
);

/* ------------------------------------------------------------------ */
/* ABI encode / decode helpers                                         */
/* ------------------------------------------------------------------ */

export function padAddress(a: string): string {
  return a.toLowerCase().replace(/^0x/, "").padStart(64, "0");
}

/** Unsigned or two's-complement signed integer → 32-byte hex word (no 0x). */
export function padInt(n: bigint | number, bits: number): string {
  const mask = (BigInt(1) << BigInt(bits)) - BigInt(1);
  return (BigInt(n) & mask).toString(16).padStart(64, "0");
}

export function wordAt(hex: string, i: number): bigint {
  const h = hex.startsWith("0x") ? hex.slice(2) : hex;
  return BigInt("0x" + h.slice(i * 64, (i + 1) * 64));
}

/** Decode a dynamic string return (name()/symbol()). */
export function decodeString(hex: string): string {
  const h = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (h.length < 128) return "";
  const len = Number(BigInt("0x" + h.slice(64, 128)));
  if (!Number.isFinite(len) || len < 0 || len > 1024) return "";
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++)
    bytes[i] = parseInt(h.slice(128 + i * 2, 130 + i * 2), 16);
  try {
    return new TextDecoder().decode(bytes);
  } catch {
    return "";
  }
}

/** Decode int24 from a word (two's complement). */
export function decodeInt24(w: bigint): number {
  let v = Number(w & BigInt("0xffffff"));
  if (v >= 2 ** 23) v -= 2 ** 24;
  return v;
}

/* ------------------------------------------------------------------ */
/* TickMath — BigInt port of Uniswap v4-core TickMath.getSqrtPriceAtTick */
/* Constants transcribed from v4-core src/libraries/TickMath.sol.       */
/* ------------------------------------------------------------------ */

const TICK_CONSTANTS: Array<[number, bigint]> = [
  [0x1, BigInt("0xfffcb933bd6fad37aa2d162d1a594001")],
  [0x2, BigInt("0xfff97272373d413259a46990580e213a")],
  [0x4, BigInt("0xfff2e50f5f656932ef12357cf3c7fdcc")],
  [0x8, BigInt("0xffe5caca7e10e4e61c3624eaa0941cd0")],
  [0x10, BigInt("0xffcb9843d60f6159c9db58835c926644")],
  [0x20, BigInt("0xff973b41fa98c081472e6896dfb254c0")],
  [0x40, BigInt("0xff2ea16466c96a3843ec78b326b52861")],
  [0x80, BigInt("0xfe5dee046a99a2a811c461f1969c3053")],
  [0x100, BigInt("0xfcbe86c7900a88aedcffc83b479aa3a4")],
  [0x200, BigInt("0xf987a7253ac413176f2b074cf7815e54")],
  [0x400, BigInt("0xf3392b0822b70005940c7a398e4b70f3")],
  [0x800, BigInt("0xe7159475a2c29b7443b29c7fa6e889d9")],
  [0x1000, BigInt("0xd097f3bdfd2022b8845ad8f792aa5825")],
  [0x2000, BigInt("0xa9f746462d870fdf8a65dc1f90e061e5")],
  [0x4000, BigInt("0x70d869a156d2a1b890bb3df62baf32f7")],
  [0x8000, BigInt("0x31be135f97d08fd981231505542fcfa6")],
  [0x10000, BigInt("0x9aa508b5b7a84e1c677de54f3e99bc9")],
  [0x20000, BigInt("0x5d6af8dedb81196699c329225ee604")],
  [0x40000, BigInt("0x2216e584f5fa1ea926041bedfe98")],
  [0x80000, BigInt("0x48a170391f7dc42444e8fa2")],
];

export const MIN_TICK = -887272;
export const MAX_TICK = 887272;
const Q128 = BigInt(1) << BigInt(128);
const Q96 = BigInt(1) << BigInt(96);

/** sqrt(1.0001^tick) * 2^96 as bigint. */
export function getSqrtPriceAtTick(tick: number): bigint {
  if (!Number.isInteger(tick) || tick < MIN_TICK || tick > MAX_TICK)
    throw new Error(`tick out of range: ${tick}`);
  const absTick = tick < 0 ? -tick : tick;
  let price: bigint;
  if (absTick & 0x1) {
    price = TICK_CONSTANTS[0][1];
  } else {
    price = BigInt(1) << BigInt(128);
  }
  for (let i = 1; i < TICK_CONSTANTS.length; i++) {
    const [bit, c] = TICK_CONSTANTS[i];
    if (absTick & bit) price = (price * c) >> BigInt(128);
  }
  if (tick > 0) price = ((BigInt(1) << BigInt(256)) - BigInt(1)) / price;
  // Q128.128 → Q64.96, rounding up (matches the Solidity).
  return ((price + (BigInt(1) << BigInt(32)) - BigInt(1)) >> BigInt(32)) & ((BigInt(1) << BigInt(160)) - BigInt(1));
}

/* ------------------------------------------------------------------ */
/* LiquidityAmounts — token amounts for (liquidity, tick range, price) */
/* ------------------------------------------------------------------ */

export interface PositionAmounts {
  amount0: bigint;
  amount1: bigint;
}

/** Mirrors v4-core LiquidityAmounts.getAmountsForLiquidity. */
export function getAmountsForLiquidity(
  sqrtPriceX96: bigint,
  sqrtPriceAX96: bigint,
  sqrtPriceBX96: bigint,
  liquidity: bigint
): PositionAmounts {
  let sqrtA = sqrtPriceAX96;
  let sqrtB = sqrtPriceBX96;
  if (sqrtA > sqrtB) [sqrtA, sqrtB] = [sqrtB, sqrtA];
  if (sqrtPriceX96 <= sqrtA) {
    return {
      amount0: getAmount0ForLiquidity(sqrtA, sqrtB, liquidity),
      amount1: BigInt(0),
    };
  }
  if (sqrtPriceX96 >= sqrtB) {
    return {
      amount0: BigInt(0),
      amount1: getAmount1ForLiquidity(sqrtA, sqrtB, liquidity),
    };
  }
  return {
    amount0: getAmount0ForLiquidity(sqrtPriceX96, sqrtB, liquidity),
    amount1: getAmount1ForLiquidity(sqrtA, sqrtPriceX96, liquidity),
  };
}

function getAmount0ForLiquidity(
  sqrtAX96: bigint,
  sqrtBX96: bigint,
  liquidity: bigint
): bigint {
  // L * (sqrtB - sqrtA) * 2^96 / (sqrtB * sqrtA)
  return (liquidity * (sqrtBX96 - sqrtAX96) * Q96) / (sqrtBX96 * sqrtAX96);
}

function getAmount1ForLiquidity(
  sqrtAX96: bigint,
  sqrtBX96: bigint,
  liquidity: bigint
): bigint {
  // L * (sqrtB - sqrtA) / 2^96
  return (liquidity * (sqrtBX96 - sqrtAX96)) / Q96;
}

/* ------------------------------------------------------------------ */
/* RPC plumbing — sequential, rate-limit aware                         */
/* ------------------------------------------------------------------ */

export interface RpcOptions {
  /** ms to wait between individual RPC calls (default 150) */
  pacingMs?: number;
  /** per-call timeout ms (default 15000) */
  timeoutMs?: number;
  /** retries on 429 / transient failure (default 3) */
  retries?: number;
  userAgent?: string;
}

const DEFAULT_UA =
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

export class RpcClient {
  private pacing: number;
  private timeoutMs: number;
  private retries: number;
  private ua: string;
  private lastCall = 0;
  /**
   * Serializes all RPC traffic through one client: concurrent callers
   * queue up, so pacing is honored and the public RPC's rate limiter
   * isn't tripped by bursts.
   */
  private queue: Promise<void> = Promise.resolve();

  constructor(
    readonly rpcUrl: string,
    opts: RpcOptions = {}
  ) {
    this.pacing = opts.pacingMs ?? 150;
    this.timeoutMs = opts.timeoutMs ?? 15000;
    this.retries = opts.retries ?? 3;
    this.ua = opts.userAgent ?? DEFAULT_UA;
  }

  private async pace(): Promise<void> {
    const wait = this.lastCall + this.pacing - Date.now();
    if (wait > 0) await new Promise((r) => setTimeout(r, wait));
    this.lastCall = Date.now();
  }

  /** Raw JSON-RPC call. Returns the `result`, or null on any failure. */
  async call(method: string, params: unknown[]): Promise<unknown> {
    const run = async (): Promise<unknown> => {
      for (let attempt = 0; attempt <= this.retries; attempt++) {
        await this.pace();
        try {
          const ctrl = new AbortController();
          const t = setTimeout(() => ctrl.abort(), this.timeoutMs);
          let json: {
            result?: unknown;
            error?: { code?: number; message?: string };
          };
          try {
            const res = await fetch(this.rpcUrl, {
              method: "POST",
              headers: {
                "Content-Type": "application/json",
                "User-Agent": this.ua,
              },
              body: JSON.stringify({
                jsonrpc: "2.0",
                id: 1,
                method,
                params,
              }),
              signal: ctrl.signal,
            });
            json = (await res.json()) as typeof json;
          } finally {
            clearTimeout(t);
          }
          if (json.error) {
            // 429 / rate limits: back off and retry. Anything else is a
            // hard failure for this call (e.g. revert on eth_call).
            if (
              json.error.code === 429 ||
              /too many|rate limit|throttl/i.test(json.error.message ?? "")
            ) {
              await new Promise((r) =>
                setTimeout(r, 1000 * (attempt + 1) + Math.random() * 500)
              );
              continue;
            }
            return null;
          }
          return json.result ?? null;
        } catch {
          // network / timeout: brief backoff, then retry
          await new Promise((r) => setTimeout(r, 500 * (attempt + 1)));
        }
      }
      return null;
    };
    const p = this.queue.then(run);
    this.queue = p.then(
      () => undefined,
      () => undefined
    );
    return p;
  }

  /** eth_call returning raw 0x hex, or null on failure/revert. */
  async ethCall(to: string, data: string): Promise<string | null> {
    const r = await this.call("eth_call", [{ to, data }, "latest"]);
    return typeof r === "string" && r.startsWith("0x") ? r : null;
  }

  /** eth_getLogs, or null on failure. */
  async getLogs(filter: Record<string, unknown>): Promise<Array<{
    blockNumber: string;
    logIndex: string;
    transactionHash: string;
    topics: string[];
    data: string;
  }> | null> {
    const r = await this.call("eth_getLogs", [filter]);
    return Array.isArray(r) ? (r as never) : null;
  }

  async blockNumber(): Promise<number | null> {
    const r = await this.call("eth_blockNumber", []);
    if (typeof r !== "string") return null;
    const n = parseInt(r, 16);
    return Number.isFinite(n) ? n : null;
  }

  async blockTimestamp(blockNumber: number): Promise<number | null> {
    const r = await this.call("eth_getBlockByNumber", [
      "0x" + blockNumber.toString(16),
      false,
    ]);
    const ts =
      r && typeof r === "object"
        ? (r as { timestamp?: string }).timestamp
        : undefined;
    if (typeof ts !== "string") return null;
    const n = parseInt(ts, 16);
    return Number.isFinite(n) ? n : null;
  }
}

/* ------------------------------------------------------------------ */
/* Position discovery                                                  */
/* ------------------------------------------------------------------ */

export interface DiscoveredPosition {
  tokenId: bigint;
  /** block the mint Transfer landed in (for "Created") */
  mintBlock: number;
}

const ZERO_TOPIC = "0x" + "0".repeat(64);

/**
 * Find v4 position NFTs currently owned by `wallet`.
 *
 * Scans PositionManager Transfer events in both directions from block 0
 * (topic-filtered, block-paginated past the node's 10k-log page cap) and
 * nets mints/receives against sends/burns by latest event. Each survivor
 * is confirmed with ownerOf, since a burn reverts there.
 */
export async function discoverPositions(
  rpc: RpcClient,
  wallet: string,
  fromBlock = 0
): Promise<DiscoveredPosition[]> {
  const latest = await rpc.blockNumber();
  if (latest === null) throw new Error("could not read latest block");
  if (fromBlock > latest) return [];
  const w = "0x" + wallet.toLowerCase().replace(/^0x/, "").padStart(64, "0");

  // tokenId -> { lastIsReceive, mintBlock }; ordered by (block, logIndex)
  const state = new Map<string, { receive: boolean; mintBlock: number }>();

  for (const dir of ["to", "from"] as const) {
    const topics =
      dir === "to"
        ? [TRANSFER_TOPIC, null, w]
        : [TRANSFER_TOPIC, w, null];
    let cursor = fromBlock;
    const seen = new Set<string>();
    // Page past the node's result cap.
    for (;;) {
      const logs = await rpc.getLogs({
        address: V4_POSITION_MANAGER,
        topics,
        fromBlock: "0x" + cursor.toString(16),
        toBlock: "0x" + latest.toString(16),
      });
      if (!logs) throw new Error("Transfer log scan failed");
      let progressed = false;
      for (const l of logs) {
        const key = `${l.blockNumber}:${l.logIndex}`;
        if (seen.has(key)) continue;
        seen.add(key);
        progressed = true;
        const tokenId = BigInt(l.topics[3]).toString();
        const block = parseInt(l.blockNumber, 16);
        const from = l.topics[1];
        const isMint = dir === "to" && from === ZERO_TOPIC;
        const prev = state.get(tokenId);
        state.set(tokenId, {
          receive: dir === "to",
          mintBlock: isMint ? block : (prev?.mintBlock ?? block),
        });
        if (block > cursor) cursor = block;
      }
      // A full page means there may be more; continue from the last block.
      if (logs.length >= 10000 && progressed) continue;
      break;
    }
  }

  const candidates: DiscoveredPosition[] = [];
  state.forEach((s, id) => {
    if (s.receive) candidates.push({ tokenId: BigInt(id), mintBlock: s.mintBlock });
  });
  if (candidates.length === 0) return [];

  // Confirm current ownership (burned tokens revert in ownerOf).
  const ownerSel = selector("ownerOf(uint256)");
  const held: DiscoveredPosition[] = [];
  for (const c of candidates) {
    const raw = await rpc.ethCall(
      V4_POSITION_MANAGER,
      "0x" + ownerSel + padInt(c.tokenId, 256)
    );
    if (!raw || raw.length < 66) continue;
    const owner = "0x" + raw.slice(-40).toLowerCase();
    if (owner === wallet.toLowerCase()) held.push(c);
  }
  return held;
}

/* ------------------------------------------------------------------ */
/* Position + pool reads                                              */
/* ------------------------------------------------------------------ */

export interface PoolKey {
  currency0: string;
  currency1: string;
  fee: number;
  tickSpacing: number;
  hooks: string;
}

export interface PositionState {
  poolKey: PoolKey;
  poolId: string;
  tickLower: number;
  tickUpper: number;
  liquidity: bigint;
  sqrtPriceX96: bigint;
  tick: number;
  lpFee: number;
  poolLiquidity: bigint;
  /** feeGrowthInside at the position's range (X128) */
  feeGrowthInside0: bigint;
  feeGrowthInside1: bigint;
  /** feeGrowthInside snapshot stored when fees were last collected */
  feeGrowthInside0Last: bigint;
  feeGrowthInside1Last: bigint;
}

/** PoolId = keccak256(abi.encode(poolKey)). */
export function poolIdOf(key: PoolKey): string {
  const enc =
    padAddress(key.currency0) +
    padAddress(key.currency1) +
    padInt(key.fee, 24) +
    padInt(key.tickSpacing, 24) +
    padAddress(key.hooks);
  const bytes = new Uint8Array(enc.length / 2);
  for (let i = 0; i < bytes.length; i++)
    bytes[i] = parseInt(enc.slice(i * 2, i * 2 + 2), 16);
  return keccak256Hex(bytes);
}

function bytes32Of(tokenId: bigint): string {
  return "0x" + padInt(tokenId, 256);
}

/**
 * Read everything the dashboard needs for one position. Returns null when
 * the position no longer exists or any critical read fails (callers skip
 * it — a revert between discovery and read is normal for burned tokens).
 */
export async function readPositionState(
  rpc: RpcClient,
  tokenId: bigint
): Promise<PositionState | null> {
  const tidHex = padInt(tokenId, 256);
  const infoRaw = await rpc.ethCall(
    V4_POSITION_MANAGER,
    "0x" + selector("getPoolAndPositionInfo(uint256)") + tidHex
  );
  if (!infoRaw || infoRaw.length < 2 + 64 * 6) return null;
  const w0 = wordAt(infoRaw, 0);
  const w1 = wordAt(infoRaw, 1);
  const currency0 = "0x" + w0.toString(16).padStart(64, "0").slice(-40);
  const currency1 = "0x" + w1.toString(16).padStart(64, "0").slice(-40);
  const fee = Number(wordAt(infoRaw, 2) & BigInt("0xffffff"));
  const tickSpacing = decodeInt24(wordAt(infoRaw, 3));
  const w4 = wordAt(infoRaw, 4);
  const hooks = "0x" + w4.toString(16).padStart(64, "0").slice(-40);
  const pinfo = wordAt(infoRaw, 5);
  if (pinfo === BigInt(0)) return null; // burned / never minted
  const tickLower = decodeInt24((pinfo >> BigInt(8)) & BigInt("0xffffff"));
  const tickUpper = decodeInt24((pinfo >> BigInt(32)) & BigInt("0xffffff"));
  const poolKey: PoolKey = { currency0, currency1, fee, tickSpacing, hooks };
  const poolId = poolIdOf(poolKey);

  const liqRaw = await rpc.ethCall(
    V4_POSITION_MANAGER,
    "0x" + selector("getPositionLiquidity(uint256)") + tidHex
  );
  if (!liqRaw) return null;
  const liquidity = BigInt(liqRaw);

  // Pool state via StateView (PoolManager.getSlot0 reverts on this chain).
  const slotRaw = await rpc.ethCall(
    V4_STATE_VIEW,
    "0x" + selector("getSlot0(bytes32)") + poolId.slice(2)
  );
  if (!slotRaw || slotRaw.length < 2 + 64 * 4) return null;
  const sqrtPriceX96 = wordAt(slotRaw, 0);
  const tick = decodeInt24(wordAt(slotRaw, 1));
  const lpFee = Number(wordAt(slotRaw, 3) & BigInt("0xffffff"));
  if (sqrtPriceX96 === BigInt(0)) return null;

  const poolLiqRaw = await rpc.ethCall(
    V4_STATE_VIEW,
    "0x" + selector("getLiquidity(bytes32)") + poolId.slice(2)
  );
  const poolLiquidity = poolLiqRaw ? BigInt(poolLiqRaw) : BigInt(0);

  const fgiRaw = await rpc.ethCall(
    V4_STATE_VIEW,
    "0x" +
      selector("getFeeGrowthInside(bytes32,int24,int24)") +
      poolId.slice(2) +
      padInt(tickLower, 24) +
      padInt(tickUpper, 24)
  );
  if (!fgiRaw || fgiRaw.length < 2 + 64 * 2) return null;

  // The position's stored fee snapshot: owner is the PositionManager
  // contract itself, salt is bytes32(tokenId).
  const posRaw = await rpc.ethCall(
    V4_STATE_VIEW,
    "0x" +
      selector("getPositionInfo(bytes32,address,int24,int24,bytes32)") +
      poolId.slice(2) +
      padAddress(V4_POSITION_MANAGER) +
      padInt(tickLower, 24) +
      padInt(tickUpper, 24) +
      bytes32Of(tokenId).slice(2)
  );
  if (!posRaw || posRaw.length < 2 + 64 * 3) return null;

  return {
    poolKey,
    poolId,
    tickLower,
    tickUpper,
    liquidity,
    sqrtPriceX96,
    tick,
    lpFee,
    poolLiquidity,
    feeGrowthInside0: wordAt(fgiRaw, 0),
    feeGrowthInside1: wordAt(fgiRaw, 1),
    feeGrowthInside0Last: wordAt(posRaw, 1),
    feeGrowthInside1Last: wordAt(posRaw, 2),
  };
}

/** Unclaimed fees for a position (fee-growth accounting, mod 2^256). */
export function unclaimedFees(st: PositionState): {
  fees0: bigint;
  fees1: bigint;
} {
  const MOD = (BigInt(1) << BigInt(256)) - BigInt(1);
  const d0 = (st.feeGrowthInside0 - st.feeGrowthInside0Last) & MOD;
  const d1 = (st.feeGrowthInside1 - st.feeGrowthInside1Last) & MOD;
  return {
    fees0: (d0 * st.liquidity) >> BigInt(128),
    fees1: (d1 * st.liquidity) >> BigInt(128),
  };
}

/* ------------------------------------------------------------------ */
/* Token metadata                                                     */
/* ------------------------------------------------------------------ */

export interface TokenMeta {
  address: string;
  symbol: string;
  name: string;
  decimals: number;
  isNative: boolean;
}

const metaCache = new Map<string, TokenMeta>();

/** name()/symbol()/decimals() for a currency; address(0) → native ETH. */
export async function tokenMeta(
  rpc: RpcClient,
  address: string
): Promise<TokenMeta> {
  const a = address.toLowerCase();
  const hit = metaCache.get(a);
  if (hit) return hit;
  if (a === V4_NATIVE) {
    const m: TokenMeta = {
      address: V4_NATIVE,
      symbol: "ETH",
      name: "Ether",
      decimals: 18,
      isNative: true,
    };
    metaCache.set(a, m);
    return m;
  }
  const [decRaw, symRaw, nameRaw] = await Promise.all([
    rpc.ethCall(a, "0x" + selector("decimals()")),
    rpc.ethCall(a, "0x" + selector("symbol()")),
    rpc.ethCall(a, "0x" + selector("name()")),
  ]);
  const decimals = decRaw ? Number(BigInt(decRaw)) : 18;
  const symbol = symRaw ? decodeString(symRaw) || "UNKNOWN" : "UNKNOWN";
  const name = nameRaw ? decodeString(nameRaw) || symbol : symbol;
  const m: TokenMeta = {
    address: a,
    symbol,
    name,
    decimals: Number.isFinite(decimals) ? decimals : 18,
    isNative: false,
  };
  metaCache.set(a, m);
  return m;
}

/** raw units → human decimal string. */
export function formatUnits(raw: bigint, decimals: number): string {
  if (decimals === 0) return raw.toString();
  const neg = raw < BigInt(0);
  const v = neg ? -raw : raw;
  let base = BigInt(1);
  for (let i = 0; i < decimals; i++) base *= BigInt(10);
  const int = v / base;
  let frac = (v % base).toString().padStart(decimals, "0");
  frac = frac.replace(/0+$/, "");
  const s = frac ? `${int}.${frac}` : int.toString();
  return neg ? `-${s}` : s;
}

/* ------------------------------------------------------------------ */
/* APR estimate from trailing swap volume                             */
/* ------------------------------------------------------------------ */

export interface AprEstimate {
  /** annualized fraction, e.g. 8.53 = 853% — null when not computable */
  apr: number | null;
  /** human basis label for the UI, e.g. "est. · 24h volume" */
  basis: string | null;
}

/**
 * Estimate the position's APR from trailing-24h Swap volume in its pool:
 *
 *   poolFees24h ≈ swapVolumeUsd * lpFee / 1e6
 *   apr ≈ poolFees24h * 365 / positionValueUsd * (positionLiq / poolLiq)
 *
 * The liquidity-share term assumes the pool's active liquidity earned the
 * volume roughly uniformly — an approximation, so callers must label the
 * result an estimate. Out-of-range positions earn nothing: apr is null.
 */
export async function estimateApr(
  rpc: RpcClient,
  st: PositionState,
  meta0: TokenMeta,
  meta1: TokenMeta,
  price0Usd: number | null,
  price1Usd: number | null,
  positionValueUsd: number | null
): Promise<AprEstimate> {
  const inRange = st.tick >= st.tickLower && st.tick < st.tickUpper;
  if (!inRange) return { apr: null, basis: "out of range" };
  if (
    positionValueUsd === null ||
    positionValueUsd <= 0 ||
    st.poolLiquidity === BigInt(0) ||
    st.liquidity === BigInt(0)
  )
    return { apr: null, basis: null };
  const latest = await rpc.blockNumber();
  if (latest === null) return { apr: null, basis: null };
  // ~24h of blocks at ~0.1s; cap the window so the log query stays cheap.
  const windowBlocks = Math.min(864000, Math.floor(latest / 2));
  if (windowBlocks <= 0) return { apr: null, basis: null };
  const logs = await rpc.getLogs({
    address: V4_POOL_MANAGER,
    topics: [SWAP_TOPIC, "0x" + st.poolId.slice(2).padStart(64, "0")],
    fromBlock: "0x" + (latest - windowBlocks).toString(16),
    toBlock: "0x" + latest.toString(16),
  });
  if (!logs || logs.length === 0) return { apr: null, basis: "no volume" };
  const s128 = (w: bigint): bigint => {
    const v = w & ((BigInt(1) << BigInt(128)) - BigInt(1));
    return v >= BigInt(1) << BigInt(127) ? v - (BigInt(1) << BigInt(128)) : v;
  };
  let vol0 = BigInt(0);
  let vol1 = BigInt(0);
  for (const l of logs) {
    const d = l.data.startsWith("0x") ? l.data.slice(2) : l.data;
    if (d.length < 128) continue;
    const a0 = s128(BigInt("0x" + d.slice(0, 64) || "0"));
    const a1 = s128(BigInt("0x" + d.slice(64, 128) || "0"));
    vol0 += a0 < BigInt(0) ? -a0 : a0;
    vol1 += a1 < BigInt(0) ? -a1 : a1;
  }
  const q0 = Number(formatUnits(vol0, meta0.decimals));
  const q1 = Number(formatUnits(vol1, meta1.decimals));
  if (!Number.isFinite(q0) || !Number.isFinite(q1)) return { apr: null, basis: null };
  const p0 = price0Usd ?? 0;
  const p1 = price1Usd ?? 0;
  // Each swap moves both sides; halve to avoid double counting.
  const volumeUsd = (q0 * p0 + q1 * p1) / 2;
  const fees24h = volumeUsd * (st.lpFee / 1e6);
  const share = Number(st.liquidity) / Number(st.poolLiquidity);
  if (!Number.isFinite(share) || share <= 0) return { apr: null, basis: null };
  const apr = ((fees24h * 365 * share) / positionValueUsd) * 100;
  if (!Number.isFinite(apr) || apr < 0) return { apr: null, basis: null };
  return { apr, basis: "est. · 24h volume" };
}

/* ------------------------------------------------------------------ */
/* High-level: positions for a set of wallets                         */
/* ------------------------------------------------------------------ */

export interface LpPositionView {
  tokenId: string;
  owner: string;
  poolId: string;
  token0: TokenMeta;
  token1: TokenMeta;
  fee: number;
  /** fee as human percent string, e.g. "0.9%" */
  feeLabel: string;
  tickSpacing: number;
  hooks: string;
  tickLower: number;
  tickUpper: number;
  tick: number;
  inRange: boolean;
  liquidity: string;
  amount0: string;
  amount1: string;
  /** price of token1 per token0 at the range bounds (human strings) */
  priceLower: string;
  priceUpper: string;
  /** share of position value in each token, 0-100 (null when unpriced) */
  pct0: number | null;
  pct1: number | null;
  price0Usd: string | null;
  price1Usd: string | null;
  valueUsd: string | null;
  fees0: string;
  fees1: string;
  feesUsd: string | null;
  apr: number | null;
  aprBasis: string | null;
  created: string | null;
  createdBlock: number | null;
}

export interface LpWalletView {
  wallet: string;
  addresses: string[];
  positions: LpPositionView[];
}

export interface PriceSource {
  /** USD price per token contract address (lowercased); native via nativeUsd(). */
  tokenUsd: (contracts: string[]) => Promise<Map<string, string>>;
  nativeUsd: () => Promise<string | null>;
}

/** sqrtPriceX96 → price of token1 per token0 (float, for display). */
export function sqrtPriceToPrice1Per0(
  sqrtPriceX96: bigint,
  dec0: number,
  dec1: number
): number {
  const ratio = Number(sqrtPriceX96) / 2 ** 96;
  const raw = ratio * ratio;
  return raw * 10 ** (dec0 - dec1);
}

function feeLabel(fee: number): string {
  if (fee === 0x800000) return "dynamic";
  const pct = fee / 1e6;
  return `${Number(pct.toFixed(4))}%`;
}

export async function buildPositionView(
  rpc: RpcClient,
  prices: PriceSource,
  owner: string,
  tokenId: bigint,
  mintBlock: number
): Promise<LpPositionView | null> {
  const st = await readPositionState(rpc, tokenId);
  if (!st) return null;
  const [meta0, meta1] = await Promise.all([
    tokenMeta(rpc, st.poolKey.currency0),
    tokenMeta(rpc, st.poolKey.currency1),
  ]);
  const sqrtA = getSqrtPriceAtTick(st.tickLower);
  const sqrtB = getSqrtPriceAtTick(st.tickUpper);
  const { amount0, amount1 } = getAmountsForLiquidity(
    st.sqrtPriceX96,
    sqrtA,
    sqrtB,
    st.liquidity
  );
  const { fees0, fees1 } = unclaimedFees(st);

  const priceMap = await prices.tokenUsd(
    [meta0, meta1].filter((m) => !m.isNative).map((m) => m.address)
  );
  const native = await prices.nativeUsd();
  const p0 = meta0.isNative ? native : (priceMap.get(meta0.address) ?? null);
  const p1 = meta1.isNative ? native : (priceMap.get(meta1.address) ?? null);
  const price0Usd = p0 !== null && Number(p0) > 0 ? p0 : null;
  const price1Usd = p1 !== null && Number(p1) > 0 ? p1 : null;

  const a0 = formatUnits(amount0, meta0.decimals);
  const a1 = formatUnits(amount1, meta1.decimals);
  const f0 = formatUnits(fees0, meta0.decimals);
  const f1 = formatUnits(fees1, meta1.decimals);

  const v0 = price0Usd !== null ? Number(a0) * Number(price0Usd) : null;
  const v1 = price1Usd !== null ? Number(a1) * Number(price1Usd) : null;
  const valueUsd =
    v0 !== null && v1 !== null && Number.isFinite(v0 + v1)
      ? (v0 + v1).toFixed(2)
      : null;
  const fv0 = price0Usd !== null ? Number(f0) * Number(price0Usd) : null;
  const fv1 = price1Usd !== null ? Number(f1) * Number(price1Usd) : null;
  const feesUsd =
    fv0 !== null && fv1 !== null && Number.isFinite(fv0 + fv1)
      ? (fv0 + fv1).toFixed(2)
      : null;
  let pct0: number | null = null;
  let pct1: number | null = null;
  if (valueUsd !== null && Number(valueUsd) > 0 && v0 !== null && v1 !== null) {
    pct0 = (v0 / Number(valueUsd)) * 100;
    pct1 = (v1 / Number(valueUsd)) * 100;
  }

  const aprEst = await estimateApr(
    rpc,
    st,
    meta0,
    meta1,
    price0Usd !== null ? Number(price0Usd) : null,
    price1Usd !== null ? Number(price1Usd) : null,
    valueUsd !== null ? Number(valueUsd) : null
  );

  let created: string | null = null;
  const ts = await rpc.blockTimestamp(mintBlock);
  if (ts !== null) created = new Date(ts * 1000).toISOString();

  return {
    tokenId: tokenId.toString(),
    owner: owner.toLowerCase(),
    poolId: st.poolId,
    token0: meta0,
    token1: meta1,
    fee: st.poolKey.fee,
    feeLabel: feeLabel(st.poolKey.fee),
    tickSpacing: st.poolKey.tickSpacing,
    hooks: st.poolKey.hooks,
    tickLower: st.tickLower,
    tickUpper: st.tickUpper,
    tick: st.tick,
    inRange: st.tick >= st.tickLower && st.tick < st.tickUpper,
    liquidity: st.liquidity.toString(),
    amount0: a0,
    amount1: a1,
    priceLower: sqrtPriceToPrice1Per0(sqrtA, meta0.decimals, meta1.decimals).toPrecision(6),
    priceUpper: sqrtPriceToPrice1Per0(sqrtB, meta0.decimals, meta1.decimals).toPrecision(6),
    pct0,
    pct1,
    price0Usd,
    price1Usd,
    valueUsd,
    fees0: f0,
    fees1: f1,
    feesUsd,
    apr: aprEst.apr,
    aprBasis: aprEst.basis,
    created,
    createdBlock: mintBlock,
  };
}
