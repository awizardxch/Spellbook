import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Spellbook Chia Relay — First-Tester Console",
  description:
    "Watch addresses, check relay status, and broadcast signed spend bundles on Chia testnet11. Read-only: never handles seeds or private keys.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
