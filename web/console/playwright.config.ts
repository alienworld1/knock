import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  use: {
    baseURL: "http://127.0.0.1:4178",
    launchOptions: { executablePath: process.env.KNOCK_TEST_BROWSER },
  },
  webServer: {
    command: "pnpm exec vite preview --host 127.0.0.1 --port 4178 --strictPort",
    url: "http://127.0.0.1:4178",
    reuseExistingServer: false,
  },
});
