// Just enough of Node for the source-scanning test, so no @types/node dependency is needed.
declare module "node:fs" {
  export function readdirSync(path: URL, options: { recursive: true }): string[];
  export function readFileSync(path: URL | string, encoding: "utf8"): string;
}