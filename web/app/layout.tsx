import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Spellbook — the agent's wallet",
  description:
    "Spellbook is a wallet stack for AI agents: the agent requests and relays, the human approves from chat, the daemon executes. Chia testnet11 now, mainnet gated.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
