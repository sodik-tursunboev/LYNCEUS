// Bundle the TypeScript with esbuild, copy the static files, and write the manifest with the pinned key.
import { build } from "esbuild";
import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";

rmSync("dist", { recursive: true, force: true });
mkdirSync("dist", { recursive: true });
await build({
  entryPoints: ["src/background.ts", "src/warning.ts", "src/popup.ts", "src/options.ts"],
  outdir: "dist",
  bundle: true,
  format: "esm",
  target: "chrome116",
  sourcemap: false,
  minify: false,
  logLevel: "warning",
});
cpSync("static", "dist", { recursive: true });
const key = readFileSync("manifest-key.txt", "utf8").trim();
const manifest = readFileSync("manifest.template.json", "utf8").replace("__KEY__", key);
writeFileSync("dist/manifest.json", manifest);
console.log("built dist/");
