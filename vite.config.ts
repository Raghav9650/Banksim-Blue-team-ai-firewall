import { defineConfig } from "vitest/config";
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [tailwindcss(), react()],
  server: {
    proxy: {
      "/api": "http://localhost:4174",
    },
  },
  build: {
    rollupOptions: {
      output: {
        manualChunks(moduleId) {
          return moduleId.includes("node_modules") ? "vendor" : undefined;
        },
      },
    },
  },
  test: {
    environment: "node",
  },
});
