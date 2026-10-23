import { copyFileSync, existsSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const source = join(root, "node_modules", "@rive-app", "canvas");
const media = join(root, "media");
mkdirSync(media, { recursive: true });
for (const file of ["rive.js", "rive.wasm"]) {
  const from = join(source, file);
  if (!existsSync(from)) {
    console.error(`Missing ${from}. Run npm install in cursor-binary-viewer.`);
    process.exit(1);
  }
  copyFileSync(from, join(media, file));
}
console.log("Copied Rive runtime into media/.");
