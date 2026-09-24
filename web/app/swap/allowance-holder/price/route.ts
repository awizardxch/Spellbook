// 0x-compatible GET proxy for indicative prices.
// Mirrors the quote proxy (../quote/route.ts) but hits the 0x price endpoint.
import { NextResponse } from "next/server";

export const dynamic = "force-dynamic";

const ZEROX_BASE = "https://api.0x.org";
const TIMEOUT_MS = 15000;

export async function GET(req: Request) {
  const apiKey = process.env.ZERO_EX_API_KEY;
  if (!apiKey) {
    return NextResponse.json(
      { error: "ZERO_EX_API_KEY not configured on this deployment" },
      { status: 503 }
    );
  }
  const url = new URL(req.url);
  const target = `${ZEROX_BASE}/swap/allowance-holder/price?${url.searchParams.toString()}`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(target, {
      headers: { "0x-api-key": apiKey, "0x-version": "v2" },
      signal: controller.signal,
      // Indicative prices go stale in seconds. Next.js caches fetch() in the
      // Data Cache by default — no-store keeps every price request live.
      cache: "no-store",
    });
    const data = await res.json().catch(() => null);
    if (!res.ok) return NextResponse.json(data, { status: res.status });
    if (data && typeof data === "object") {
      return NextResponse.json(
        { ...data, relay: "spellbook", venue: "matcha" },
        { headers: { "Cache-Control": "no-store" } }
      );
    }
    return NextResponse.json(data, {
      headers: { "Cache-Control": "no-store" },
    });
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return NextResponse.json({ error: `price relay failed: ${msg}` }, { status: 502 });
  } finally {
    clearTimeout(timer);
  }
}
