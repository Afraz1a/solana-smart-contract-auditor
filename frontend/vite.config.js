import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    proxy: {
      "/scan":        "http://localhost:8000",
      "/leaderboard": "http://localhost:8000",
      "/feedback":    "http://localhost:8000",
    },
  },
});
