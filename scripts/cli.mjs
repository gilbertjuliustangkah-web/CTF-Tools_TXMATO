import { runCtf } from "./_lib.mjs";

const args = process.argv.slice(2);
runCtf(args.length ? args : ["--help"]);