import { defineConfig } from "tsup";

export default defineConfig({
  entry: {
    index: "src/index.ts",
  },
  format: ["cjs", "esm"],
  dts: true,
  sourcemap: true,
  clean: true,
  splitting: false,
  treeshake: true,
  external: ["react", "react-dom"],
  // The component file itself starts with `"use client";` so Next.js
  // App Router treats it as a Client Component when imported. tsup +
  // rollup strip the directive from the bundle entry though; emit it
  // back at the top via `onSuccess` so RSC consumers see the boundary
  // in both CJS and ESM artifacts.
  onSuccess: async () => {
    const fs = await import("node:fs/promises");
    for (const file of ["dist/index.js", "dist/index.mjs"]) {
      try {
        const content = await fs.readFile(file, "utf8");
        if (!content.startsWith('"use client"')) {
          await fs.writeFile(file, `"use client";\n${content}`);
        }
      } catch {
        // Ignore — file may not exist yet on the first watch run.
      }
    }
  },
});
