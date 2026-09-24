// Swap quote relay for Spellbook agents.
//
// POST /api/swap/quote
// Proxies the 0x Swap API v2 (Matcha) using the operator's ZERO_EX_API_KEY
// (server-side only, never exposed). Agents call this for routing data,
// then sign with their own seed on their own daemon — the relay never
// holds funds or signs.
//
// This is the same architecture as any DEX frontend: the API key buys
// quotes, not custody. Each agent's signing key stays sovereign.
//
// Body: {
//   chainId: number,        // e.g. 4663 for Robinhood Chain
//   sellToken: string,      // hex address or 0xeeee...eeee for native
//   buyToken: string,       // hex address or 0xeeee...eeee for native
//   sellAmount: string,     // base units, as a decimal string
//   taker: string,          // the agent's wallet address
//   slippageBps?: number,   // default 50 (0.5%)
//   firm?: boolean,         // true = executable quote w/ calldata,
//                           // false = indicative price only
// }
//
// Response: the 0x API response verbatim (price or quote), plus
// { relay: "spellbook", venue: "matcha" }.

import { NextResponse } from "next/server";

export const dynamic = "force-dynamic";

const ZEROX_BASE = "https://api.0x.org";
const TIMEOUT_MS = 15000;

const NATIVE_SENTINEL = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

function isAddress(s: unknown): s is string {
  return (
    typeof s === "string" &&
    s.length === 42 &&
    s.startsWith("0x") &&
    /^[0-9a-fA-F]+$/.test(s.slice(2))
  );
}

function bad(msg: string, status = 400) {
  return NextResponse.json({ error: msg }, { status });
}

export async function POST(req: Request) {
  const apiKey = process.env.ZERO_EX_API_KEY;
  if (!apiKey) {
    return bad("ZERO_EX_API_KEY not configured on this deployment", 503);
  }

  let body: Record<string, unknown>;
  try {
    body = await req.json();
  } catch {
    return bad("invalid JSON body");
  }

  const chainId = body.chainId;
  const sellToken = body.sellToken;
  const buyToken = body.buyToken;
  const sellAmount = body.sellAmount;
  const taker = body.taker;
  const slippageBps =
    typeof body.slippageBps === "number" ? body.slippageBps : 50;
  const firm = body.firm !== false; // default to firm quote

  if (typeof chainId !== "number" || !Number.isInteger(chainId) || chainId <= 0) {
    return bad("chainId must be a positive integer");
  }
  for (const [name, tok] of [
    ["sellToken", sellToken],
    ["buyToken", buyToken],
  ] as const) {
    if (tok !== NATIVE_SENTINEL && !isAddress(tok)) {
      return bad(`${name} must be a 0x address or ${NATIVE_SENTINEL}`);
    }
  }
  if (typeof sellAmount !== "string" || !/^[1-9][0-9]*$/.test(sellAmount)) {
    return bad("sellAmount must be a positive integer as a decimal string");
  }
  if (!isAddress(taker)) {
    return bad("taker must be a 0x address");
  }
  if (
    typeof slippageBps !== "number" ||
    !(slippageBps > 0 && slippageBps <= 500)
  ) {
    return bad("slippageBps must be in (0, 500]");
  }

  const endpoint = firm
    ? "/swap/allowance-holder/quote"
    : "/swap/allowance-holder/price";
  const params = new URLSearchParams({
    chainId: String(chainId),
    sellToken: sellToken as string,
    buyToken: buyToken as string,
    sellAmount: sellAmount as string,
    taker: taker as string,
    slippageBps: String(slippageBps),
  });

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(`${ZEROX_BASE}${endpoint}?${params}`, {
      headers: {
        "0x-api-key": apiKey,
        "0x-version": "v2",
      },
      signal: controller.signal,
    });
    const data = await res.json().catch(() => null);
    if (!res.ok) {
      return NextResponse.json(
        {
          error: "0x API error",
          status: res.status,
          detail: data,
          relay: "spellbook",
          venue: "matcha",
        },
        { status: 502 }
      );
    }
    return NextResponse.json({ ...data, relay: "spellbook", venue: "matcha" });
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return bad(`quote relay failed: ${msg}`, 502);
  } finally {
    clearTimeout(timer);
  }
}
