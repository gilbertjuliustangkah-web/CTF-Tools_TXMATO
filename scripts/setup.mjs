import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync } from "node:fs";
import { BASE, pythonBin, venvPython } from "./_lib.mjs";

const checkOnly = process.argv.includes("--check");

const venv = venvPython();
const python = pythonBin();

console.log("[ctf] checking python...");

if (!checkOnly) {
  if (!venv) {
    console.log("[ctf] creating virtual environment...");
    const r = spawnSync(python, ["-m", "venv", ".venv"], { cwd: BASE, stdio: "inherit" });
    if (r.status !== 0) {
      console.error("[ctf] failed to create venv");
      process.exit(1);
    }
  }

  console.log("[ctf] installing python dependencies...");
  const py = venvPython() || python;
  const r2 = spawnSync(py, ["-m", "pip", "install", "-e", ".[dev]", "--quiet"], { cwd: BASE, stdio: "inherit" });
  if (r2.status !== 0) {
    console.error("[ctf] pip install failed");
    process.exit(1);
  }
}

if (!existsSync(`${BASE}/workspace`)) {
  console.log("[ctf] creating workspace directory...");
  mkdirSync(`${BASE}/workspace`, { recursive: true });
}

console.log("[ctf] setup complete. Run `npm start` to launch the dashboard.");