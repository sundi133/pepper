import path from "path";
import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  test: {
    environment: "node",
    include: ["src/**/*.test.ts", "eval/**/*.test.ts", "ide/pepper-lsp/src/**/*.test.ts"],
    setupFiles: ["./vitest.setup.ts"],
  },
});
