import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = dirname(fileURLToPath(import.meta.url)); // cwd is the repo root when run via npm, script dir is scripts/
const BASE = join(ROOT, "..");

const PY = pythonBin();

export function pythonBin() {
  const onPath = spawnSync("python", ["--version"], { stdio: "ignore" }).status === 0;
  const onPath3 = spawnSync("python3", ["--version"], { stdio: "ignore" }).status === 0;
  if (onPath) return "python";
  if (onPath3) return "python3";
  return "python";
}

export function venvPython() {
  const win = join(BASE, ".venv", "Scripts", "python.exe");
  if (existsSync(win)) return win;
  const posix = join(BASE, ".venv", "bin", "python");
  if (existsSync(posix)) return posix;
  return null;
}

// Run the toolkit CLI via the venv executable, falling back to the plain interpreter.
export function runCtf(args, opts = {}) {
  const py = venvPython() || PY;
  return spawnSync(py, ["-m", "ctf.cli.main", ...args], {
    cwd: BASE,
    stdio: opts.stdio ?? "inherit",
    encoding: "utf-8",
  });
}

export { ROOT, BASE };