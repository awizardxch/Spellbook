// 0x-compatible GET proxy for the Spellbook swap quote relay.
//
// GET /swap/allowance-holder/quote?chainId=...&sellToken=...&...
// GET /swap/allowance-holder/price?chainId=...&sellToken=...&...
//
// These mirror the 0x Swap API v2 endpoints so the Spellbook daemon's
// ZeroExClient works unchanged — just set ZEROX_BASE_URL to the
// deployment origin (e.g. https://spellbook.awizard.dev). The operator's
// ZERO_EX_API_KEY stays server-side; the daemon still signs with its own
// seed. The relay never holds funds or signs.

import { NextResponse } from "next/server";

export const dynamic = "force-dynamic";

const ZEROX_BASE = "https://api.0x.org";
const TIMEOUT_MS = 15000;

function proxy(endpoint: "quote" | "price") {
  return async (req: Request) => {
    const apiKey = process.env.ZERO_EX_API_KEY;
    if (!apiKey) {
      return NextResponse.json(
        { error: "ZERO_EX_API_KEY not configured on this deployment" },
        { status: 503 }
      );
    }

    const url = new URL(req.url);
    const params = url.searchParams;

    // Pass through the 0x query params verbatim. The daemon's
    // ZeroExClient already validates chain/token/amount client-side.
    const target = `${ZEROX_BASE}/swap/allowance-holder/${endpoint}?${params.toString()}`;

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
    try {
      const res = await fetch(target, {
        headers: { "0x-api-key": apiKey, "0x-version": "v2" },
        signal: controller.signal,
      });
      const data = await res.json().catch(() => null);
      if (!res.ok) {
        return NextResponse.json(data, { status: res.status });
      }
      // Tag the response so callers know it came via the relay.
      if (data && typeof data === "object") {
        return NextResponse.json({ ...data, relay: "spellbook", venue: "matcha" });
      }
      return NextResponse.json(data);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return NextResponse.json(
        { error: `quote relay failed: ${msg}` },
        { status: 502 }
      );
    } finally {
      clearTimeout(timer);
    }
  };
}

export const GET = proxy("quote");
