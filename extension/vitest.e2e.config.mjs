import { defineConfig } from "vitest/config";

// End-to-end: a real Edge with the built extension, the real agent, native host and core.
export default defineConfig({
  test: { include: ["e2e/**/*.test.mjs"], testTimeout: 180_000, hookTimeout: 180_000, fileParallelism: false },
});
