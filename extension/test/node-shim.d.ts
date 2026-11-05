// Just enough of Node for the manifest test, so no @types/node dependency is needed.
declare module "node:fs" {
  export function readFileSync(path: URL | string, encoding: "utf8"): string;
}
declare module "node:crypto" {
  export function createHash(algorithm: "sha256"): { update(data: Uint8Array): { digest(encoding: "hex"): string } };
}
declare const Buffer: { from(data: string, encoding: "base64"): Uint8Array };
