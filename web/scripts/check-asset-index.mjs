// Prebuild gate: refuse to build when a ceremony asset or API route changed
// without public/asset-index.json being regenerated
// (python -m spellbook.asset_index write, from the repo root).
// Node built-ins only, so it runs before `npm ci` has anything to offer.
import { createHash } from "node:crypto";
import { readFileSync, readdirSync, statSync, existsSync } from "node:fs";
import { dirname, join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";

const web = join(dirname(fileURLToPath(import.meta.url)), "..");
const indexPath = join(web, "public", "asset-index.json");
const raw = readFileSync(indexPath);
const index = JSON.parse(raw.toString("utf8"));
const problems = [];

const sha256 = (b) => createHash("sha256").update(b).digest("hex");
const sri = (b) => "sha384-" + createHash("sha384").update(b).digest("base64");

const listed = new Set();
for (const e of [...index.pages, ...index.assets]) {
  listed.add(e.path);
  const file = join(web, "public", ...e.path.split("/").filter(Boolean));
  if (!existsSync(file)) { problems.push(`${e.path}: listed but missing`); continue; }
  const b = readFileSync(file);
  if (sha256(b) !== e.sha256) problems.push(`${e.path}: sha256 changed`);
  if (sri(b) !== e.sri) problems.push(`${e.path}: SRI changed`);
}
for (const n of readdirSync(join(web, "public", "ceremony"))) {
  if (!listed.has(`/ceremony/${n}`)) problems.push(`/ceremony/${n}: not in the index`);
}

const routes = [];
const walk = (d) => {
  for (const n of readdirSync(d)) {
    const p = join(d, n);
    if (statSync(p).isDirectory()) walk(p);
    else if (/^route\.(ts|tsx|js)$/.test(n)) routes.push(p);
  }
};
walk(join(web, "app", "api"));
const byPath = new Map(index.api_routes.map((r) => [r.path, r]));
for (const p of routes) {
  const route = "/" + relative(join(web, "app"), dirname(p)).split(sep).join("/");
  const r = byPath.get(route);
  if (!r) { problems.push(`${route}: API route not in the index`); continue; }
  byPath.delete(route);
  const src = Buffer.from(readFileSync(p).toString("latin1").replace(/\r\n/g, "\n"), "latin1");
  if (sha256(src) !== r.sha256) problems.push(`${route}: route source changed`);
}
for (const route of byPath.keys()) problems.push(`${route}: indexed but no route file`);

const mirror = join(web, "..", "ceremony", "asset-index.json");
if (existsSync(mirror) && !readFileSync(mirror).equals(raw))
  problems.push("../ceremony/asset-index.json differs from public/asset-index.json");

if (problems.length) {
  for (const p of problems) process.stderr.write(`asset-index: ${p}\n`);
  process.stderr.write("asset-index: stale. From the repo root run: " +
    "PYTHONPATH=src python -m spellbook.asset_index write\n");
  process.exit(1);
}
process.stdout.write(`asset index current (${listed.size} ceremony files, ` +
  `${index.api_routes.length} API routes), sha256 ${sha256(raw)}\n`);
