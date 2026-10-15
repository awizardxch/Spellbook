/** @type {import('next').NextConfig} */
// The ceremony pages' CSP lives in the asset index (one source of truth:
// src/spellbook/asset_index.py writes it there and into each page's meta
// tag), so the header and the published hashes can never disagree.
const assetIndex = require("./public/asset-index.json");

const ceremonyHeaders = [
  { key: "Content-Security-Policy", value: assetIndex.ceremony_csp },
  { key: "Referrer-Policy", value: "no-referrer" },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "X-Frame-Options", value: "DENY" },
  { key: "Cross-Origin-Opener-Policy", value: "same-origin" },
  { key: "Cross-Origin-Resource-Policy", value: "same-origin" },
  {
    key: "Permissions-Policy",
    value: "camera=(), microphone=(), geolocation=(), payment=(), usb=(), clipboard-read=()",
  },
  { key: "Cache-Control", value: "no-cache" },
];

const nextConfig = {
  reactStrictMode: true,
  async headers() {
    return [
      { source: "/ceremony/:path*", headers: ceremonyHeaders },
      {
        source: "/asset-index.json",
        headers: [
          { key: "Cache-Control", value: "no-cache" },
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "Access-Control-Allow-Origin", value: "*" },
        ],
      },
    ];
  },
};

module.exports = nextConfig;
