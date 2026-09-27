import { NextRequest, NextResponse } from "next/server";
import { execFile } from "child_process";
import { promisify } from "util";

const execFileAsync = promisify(execFile);

/**
 * POST /api/security/reveal
 * 
 * Human-authenticated key reveal. The agent cannot call this — it requires
 * the human's dashboard session (verified via the auth cookie).
 * 
 * Body: { type: "mnemonic" | "evm-key" | "chia-key", password: string }
 * 
 * The password is the human's dashboard password. It's verified against
 * the stored hash, then the key is revealed via the Python recovery tool.
 * 
 * SECURITY: This endpoint MUST NOT be accessible to the agent. The auth
 * middleware verifies a human session (not an agent API token).
 */
export async function POST(req: NextRequest) {
  try {
    // Verify human session (not agent token)
    // The auth middleware sets this header for verified human sessions
    const sessionType = req.headers.get("x-session-type");
    if (sessionType !== "human") {
      return NextResponse.json(
        { error: "Human authentication required" },
        { status: 403 }
      );
    }

    const { type, password } = await req.json();
    
    if (!type || !password) {
      return NextResponse.json(
        { error: "Type and password required" },
        { status: 400 }
      );
    }

    if (!["mnemonic", "evm-key", "chia-key"].includes(type)) {
      return NextResponse.json(
        { error: "Invalid type" },
        { status: 400 }
      );
    }

    // Verify password (implement against your auth system)
    // TODO: Replace with actual password verification
    const passwordValid = await verifyPassword(password);
    if (!passwordValid) {
      return NextResponse.json(
        { error: "Invalid password" },
        { status: 401 }
      );
    }

    // Reveal the key via Python tool
    // The Python script reads from the seed file (0600, spellbook user only)
    const { stdout } = await execFileAsync("python3", [
      "-m", "spellbook.recovery",
      "reveal", type,
    ], {
      // Run as the spellbook user who owns the seed file
      // (implement via sudo or setuid as appropriate for your setup)
      timeout: 10000,
    });

    const value = stdout.trim();
    if (!value) {
      throw new Error("No key returned");
    }

    // Log the reveal (audit trail, no key material)
    console.log(`[security] Human revealed ${type} at ${new Date().toISOString()}`);

    return NextResponse.json({ value });
  } catch (e) {
    console.error("[security] Reveal failed:", e);
    return NextResponse.json(
      { error: "Reveal failed" },
      { status: 500 }
    );
  }
}

async function verifyPassword(password: string): Promise<boolean> {
  // TODO: Implement against your auth system
  // This should verify the human's dashboard password
  // For now, this is a placeholder — DO NOT deploy without implementing
  throw new Error("Password verification not implemented");
}
