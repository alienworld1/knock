import tailwindcss from "@tailwindcss/vite";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [tailwindcss()],
  build: {
    outDir: "../../cmd/knock/consoleassets/dist",
    emptyOutDir: true,
    license: { fileName: "assets/licenses.txt" },
  },
});
