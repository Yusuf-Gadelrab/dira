#!/usr/bin/env node
// Thin launcher: DIRA is a zero-dependency Python tool. This finds a working
// runner (already-installed module, uvx, or pipx) and hands off to it.
const { spawnSync } = require("node:child_process");

const PKG = "dira-scan==1.2.0";
const args = process.argv.slice(2);

const CANDIDATES = [
  ["python3", ["-m", "dira"]],
  ["python", ["-m", "dira"]],
  ["dira", []],
  ["uvx", ["--quiet", "--from", PKG, "dira"]],
  ["pipx", ["run", "--spec", PKG, "dira"]],
];

// A candidate counts as usable only if `--version` actually prints DIRA's banner.
function usable(cmd, pre) {
  const r = spawnSync(cmd, [...pre, "--version"], { encoding: "utf8", timeout: 180000 });
  return !r.error && r.status === 0 && /^dira\s+\d/.test((r.stdout || "").trim());
}

for (const [cmd, pre] of CANDIDATES) {
  if (!usable(cmd, pre)) continue;
  const run = spawnSync(cmd, [...pre, ...args], { stdio: "inherit" });
  process.exit(run.status === null ? 1 : run.status);
}

console.error(
  "dira: no working Python runner found (needs Python 3.9+).\n" +
  "  fastest:  brew install uv        # then re-run: npx dira-scan .\n" +
  "  or:       pipx install dira-scan\n" +
  "  or:       pip install dira-scan"
);
process.exit(127);
