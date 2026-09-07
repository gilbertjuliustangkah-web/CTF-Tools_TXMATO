import { existsSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { BASE, venvPython } from "./_lib.mjs";

const py = venvPython();

if (!py) {
  console.error("[ctf] venv not found. run `npm run setup` first.");
  process.exit(1);
}

const r = spawnSync(py, ["-m", "pytest", ...process.argv.slice(2)], {
  cwd: BASE,
  stdio: "inherit",
});

process.exit(r.status ?? 1);