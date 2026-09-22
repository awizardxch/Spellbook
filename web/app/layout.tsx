import type { Metadata } from "next";
import "./globals.css";
import { GridEnergy } from "./grid-energy";

export const metadata: Metadata = {
  title: "Spellbook — the agent's wallet",
  description:
    "Spellbook is a wallet stack for AI agents: the agent requests and relays, the human approves from chat, the daemon executes. Chia testnet11 now, mainnet balances live in the dashboard.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <div className="app-background" aria-hidden="true">
          <GridEnergy />
        </div>
        <div className="app-shell">{children}</div>
      </body>
    </html>
  );
}
