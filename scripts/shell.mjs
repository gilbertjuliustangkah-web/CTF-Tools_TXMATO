import { runCtf } from "./_lib.mjs";

// `npm run shell` → always invokes the venv python in an interactive-style way,
// forwarding any args. Without args it drops the help. There's no separate
// sub-shell binary for this project; the CLI *is* the shell, so this just
// prints usage so users know what to run.
const args = process.argv.slice(2);
if (args.length === 0) {
  console.log("CTF Toolkit interactive shell: pass any ctf CLI arguments.\n");
}
runCtf(args.length ? args : ["--help"]);