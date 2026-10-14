import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["src/**/*.test.ts", "test/**/*.test.ts"],
    // Argon2 und KeePassXC-Aufrufe brauchen Zeit.
    testTimeout: 60_000,
    hookTimeout: 120_000,
  },
});
