#!/usr/bin/env node
/**
 * Builds vulnerability fixture ZIPs under fixtures/ for manual or CI testing.
 * Run: node scripts/generate-fixture-zips.mjs
 */
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import AdmZip from "adm-zip";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.join(__dirname, "..");
const outDir = path.join(root, "fixtures");
const srcDir = path.join(root, "fixtures", "sources");

function zipFolder(sourceLabel, outName, innerPrefix) {
  const z = new AdmZip();
  const base = path.join(srcDir, sourceLabel);
  function walk(rel = "") {
    const dir = path.join(base, rel);
    for (const name of fs.readdirSync(dir)) {
      const full = path.join(dir, name);
      const entryName = path.join(innerPrefix, rel, name).split(path.sep).join("/");
      if (fs.statSync(full).isDirectory()) walk(path.join(rel, name));
      else z.addFile(entryName, fs.readFileSync(full));
    }
  }
  walk();
  const dest = path.join(outDir, `${outName}.zip`);
  z.writeZip(dest);
  console.log("wrote", dest);
}

fs.mkdirSync(outDir, { recursive: true });

zipFolder("python-flask", "vulnerable-python-flask", "app");
zipFolder("node-express", "vulnerable-node-express", "app");
zipFolder("sql", "vulnerable-sql", "app");
zipFolder("xss", "vulnerable-xss", "app");
zipFolder("clean", "clean-project", "app");
