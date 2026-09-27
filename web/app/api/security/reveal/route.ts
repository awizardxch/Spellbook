import { NextRequest, NextResponse } from "next/server";
import { cookies } from "next/headers";
import { execFile } from "child_process";
import { promisify } from "util";
import path from "path";
import { SESSION_COOKIE, readSession } from "@/lib/auth";

const execFileAsync = promisify(execFile);

export const dynamic = "force-dynamic";

/**
 * POST /api/security/reveal
 *
 * Human-only key reveal for the dashboard Security tab.
 *
 * Auth: requires a dashboard session whose role is "viewer" — the human
 * viewer-token path. Agent sessions (role "agent") can call the other
 * dashboard APIs but get 403 here, so the agent cannot reveal keys
 * through this endpoint. There is deliberately no password beyond the
 * viewer session: the viewer token IS the human credential (timing-safe
 * compared server-side), and no password store exists to verify against.
 *
 * Body: { type: "mnemonic" | "evm-key" | "chia-key", chain?: string }
 *   chain is only used for evm-key / chia-key and defaults to
 *   evm-4663 / chia-testnet. It must match the daemon's KDF chain
 *   labels — KDF mode derives a distinct key per chain.
 *
 * The key is derived by the Python recovery tool from the daemon seed
 * file (0600, server user only) using the same KDF derivation the
 * daemon signs with. The revealed EVM key is the actual wallet key
 * for that chain — not the BIP-39 standard-derivation key, which
 * belongs to a different address.
 *
 * SECURITY: the response carries raw key material. It is returned only
 * to the human's browser over the authenticated session, shown once in
 * the UI, and never logged (the audit log below records the reveal
 * event only — type, chain, timestamp).
 */
const TYPES = ["mnemonic", "evm-key", "chia-key"] as const;
type RevealType = (typeof TYPES)[number];

const DEFAULT_CHAIN: Record<Exclude<RevealType, "mnemonic">, string> = {
  "evm-key": "evm-4663",
  "chia-key": "chia-testnet",
};

export async function POST(req: NextRequest) {
  const session = readSession(cookies().get(SESSION_COOKIE)?.value);
  if (!session || session.role !== "viewer") {
    return NextResponse.json(
      { error: "Human sign-in required" },
      { status: 403 }
    );
  }

  let body: { type?: unknown; chain?: unknown } | null = null;
  try {
    body = await req.json();
  } catch {
    body = null;
  }

  const type = body?.type;
  if (typeof type !== "string" || !(TYPES as readonly string[]).includes(type)) {
    return NextResponse.json({ error: "Invalid type" }, { status: 400 });
  }

  let chain: string | undefined;
  if (type !== "mnemonic") {
    const raw = body?.chain;
    chain =
      typeof raw === "string" && raw.length > 0
        ? raw
        : DEFAULT_CHAIN[type as Exclude<RevealType, "mnemonic">];
    // Tight allowlist: evm-<chain_id> or the known Chia chain labels.
    if (!/^(evm-\d+|chia|chia-testnet11)$/.test(chain)) {
      return NextResponse.json({ error: "Invalid chain" }, { status: 400 });
    }
  }

  const spellbookSrc = path.join(process.cwd(), "..", "src");
  const args = ["-m", "spellbook.recovery", "reveal", type];
  if (chain) args.push("--chain", chain);

  try {
    const { stdout } = await execFileAsync("python3", args, {
      timeout: 15000,
      env: { ...process.env, PYTHONPATH: spellbookSrc },
    });
    const value = stdout.trim();
    if (!value) throw new Error("empty reveal output");

    // Audit trail: event only, never the key material.
    console.log(
      `[security] viewer revealed ${type}${chain ? ` (${chain})` : ""} at ${new Date().toISOString()}`
    );
    return NextResponse.json({ value, chain: chain ?? null });
  } catch (e) {
    console.error(
      "[security] Reveal failed:",
      e instanceof Error ? e.message : e
    );
    return NextResponse.json({ error: "Reveal failed" }, { status: 500 });
  }
}
