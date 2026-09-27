import { NextRequest, NextResponse } from "next/server";
import { existsSync, statSync } from "fs";
import { homedir } from "os";
import { join } from "path";

/**
 * GET /api/security/hot-wallet
 * 
 * Returns the hot wallet status (initialized? address?).
 * Does NOT reveal the key — only the address (public info).
 * 
 * Human or agent can call this (address is not secret).
 */
export async function GET(req: NextRequest) {
  try {
    const hotKeyPath = join(homedir(), "workspace", ".spellbook", "hot.key");
    
    if (!existsSync(hotKeyPath)) {
      return NextResponse.json({ initialized: false });
    }

    // Verify permissions are 600
    const stat = statSync(hotKeyPath);
    const mode = stat.mode & 0o777;
    if (mode !== 0o600) {
      return NextResponse.json({
        initialized: false,
        error: `Insecure permissions: ${mode.toString(8)}, expected 600`,
      });
    }

    // Get the address (via Python, without revealing the key)
    const { execFile } = await import("child_process");
    const { promisify } = await import("util");
    const execFileAsync = promisify(execFile);
    
    const { stdout } = await execFileAsync("python3", [
      "-m", "spellbook.hotwallet", "address",
    ], { timeout: 5000 });
    
    const address = stdout.trim();
    
    return NextResponse.json({
      initialized: true,
      address,
    });
  } catch (e) {
    console.error("[security] Hot wallet status check failed:", e);
    return NextResponse.json(
      { initialized: false, error: "Check failed" },
      { status: 500 }
    );
  }
}
