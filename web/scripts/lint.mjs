import fs from "node:fs";
import path from "node:path";

const root = process.cwd();
const srcRoot = path.join(root, "src");
const htmlEntries = ["index.html", "choke.html", "devices.html", "fleet.html", "login.html"];
const scanRoots = [
  srcRoot,
  path.join(root, "vite.config.ts"),
  path.join(root, "package.json"),
  ...htmlEntries.map((file) => path.join(root, file))
];

const runtimeCdnPatterns = [
  /cdn\.tailwindcss\.com/i,
  /cdnjs\.cloudflare\.com/i,
  /cdn\.jsdelivr\.net/i,
  /unpkg\.com/i,
  /esm\.sh/i
];

const nextPatterns = [
  /next\.config/i,
  /\/_next\//i,
  /\b_next\b/i,
  /Next\.js/i,
  /App Router/i,
  /create-next-app/i
];

const requiredDependencies = [
  "@radix-ui/react-dialog",
  "@radix-ui/react-dropdown-menu",
  "@radix-ui/react-popover",
  "@tanstack/react-virtual",
  "cmdk",
  "d3",
  "jspdf",
  "jspdf-autotable",
  "lucide-react",
  "react",
  "react-dom",
  "zustand"
];

const requiredDevDependencies = [
  "@playwright/test",
  "@testing-library/react",
  "@vitejs/plugin-react",
  "tailwindcss",
  "typescript",
  "vite",
  "vitest"
];

const failures = [];
const files = collectFiles(scanRoots);

for (const file of files) {
  const text = fs.readFileSync(file, "utf8");
  for (const pattern of runtimeCdnPatterns) {
    if (pattern.test(text)) {
      failures.push(`${relative(file)} contains runtime CDN reference matching ${pattern}`);
    }
  }
  for (const pattern of nextPatterns) {
    if (pattern.test(text)) {
      failures.push(`${relative(file)} contains stale Next.js/static-export reference matching ${pattern}`);
    }
  }
}

checkEventSource(files);
checkDynamicImports(files);
checkDependencies();

if (failures.length > 0) {
  console.error("frontend lint failed:");
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

console.log("frontend lint passed");

function collectFiles(entries) {
  const out = [];
  for (const entry of entries) {
    if (!fs.existsSync(entry)) continue;
    const stat = fs.statSync(entry);
    if (stat.isDirectory()) {
      walk(entry, out);
    } else if (isScannable(entry)) {
      out.push(entry);
    }
  }
  return out.sort();
}

function walk(dir, out) {
  for (const name of fs.readdirSync(dir)) {
    const full = path.join(dir, name);
    const stat = fs.statSync(full);
    if (stat.isDirectory()) {
      walk(full, out);
    } else if (isScannable(full)) {
      out.push(full);
    }
  }
}

function isScannable(file) {
  return /\.(cjs|css|html|js|json|mjs|ts|tsx)$/.test(file);
}

function relative(file) {
  return path.relative(root, file);
}

function checkEventSource(scannedFiles) {
  const matches = [];
  for (const file of scannedFiles) {
    if (!file.startsWith(srcRoot)) continue;
    const text = fs.readFileSync(file, "utf8");
    const re = /new\s+EventSource\s*\(/g;
    let match;
    while ((match = re.exec(text))) {
      matches.push({ file, index: match.index });
    }
  }

  if (matches.length !== 1) {
    failures.push(`expected exactly one EventSource constructor in web/src, found ${matches.length}`);
    return;
  }

  const sourceFile = path.normalize(matches[0].file);
  const expected = path.normalize(path.join(root, "src/lib/stream.tsx"));
  if (sourceFile !== expected) {
    failures.push(`EventSource constructor must live in src/lib/stream.tsx, found ${relative(sourceFile)}`);
  }
}

function checkDynamicImports(scannedFiles) {
  let sawDynamicD3 = false;
  let sawDynamicJsPdf = false;
  let sawDynamicAutoTable = false;

  for (const file of scannedFiles) {
    if (!file.startsWith(srcRoot)) continue;
    const text = fs.readFileSync(file, "utf8");
    if (/import\s*\(\s*["']d3["']\s*\)/.test(text)) sawDynamicD3 = true;
    if (/import\s*\(\s*["']jspdf["']\s*\)/.test(text)) sawDynamicJsPdf = true;
    if (/import\s*\(\s*["']jspdf-autotable["']\s*\)/.test(text)) sawDynamicAutoTable = true;

    const staticD3Imports = text
      .split(/\r?\n/)
      .map((line, index) => ({ line: line.trim(), number: index + 1 }))
      .filter(({ line }) => /^import\s+(?!type\b).*["']d3["'];?$/.test(line));
    for (const item of staticD3Imports) {
      failures.push(`${relative(file)}:${item.number} statically imports d3; use import("d3")`);
    }
  }

  if (!sawDynamicD3) failures.push('missing dynamic import("d3") for the SOC graph island');
  if (!sawDynamicJsPdf) failures.push('missing dynamic import("jspdf") for PDF export');
  if (!sawDynamicAutoTable) failures.push('missing dynamic import("jspdf-autotable") for PDF tables');
}

function checkDependencies() {
  const pkgPath = path.join(root, "package.json");
  const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf8"));
  const deps = pkg.dependencies ?? {};
  const devDeps = pkg.devDependencies ?? {};

  for (const name of requiredDependencies) {
    if (!(name in deps)) failures.push(`package.json missing dependency ${name}`);
  }

  for (const name of requiredDevDependencies) {
    if (!(name in devDeps)) failures.push(`package.json missing devDependency ${name}`);
  }
}
