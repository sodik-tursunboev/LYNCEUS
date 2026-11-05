// Bundle the console with esbuild into dist/ (the core serves it at /console/).
import { build } from "esbuild";
import { cpSync, mkdirSync, rmSync } from "node:fs";

rmSync("dist", { recursive: true, force: true });
mkdirSync("dist", { recursive: true });
await build({
  entryPoints: ["src/main.tsx"],
  outfile: "dist/console.js",
  bundle: true,
  format: "esm",
  target: "chrome116",
  jsx: "automatic",
  define: { "process.env.NODE_ENV": '"production"' },
  legalComments: "none",
  logLevel: "warning",
});
cpSync("static", "dist", { recursive: true });
console.log("built dist/");