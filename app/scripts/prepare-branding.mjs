// Keep the ignored upstream frontend checkout and desktop builds on the same
// checked-in LemonVPN artwork. No image generation or extra dependency is needed.
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const appDir = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const repoRoot = resolve(appDir, "..");
const brandingDir = join(appDir, "branding", "web");
const brandingPatch = join(
  repoRoot,
  "patches",
  "doona-lemonvpn-branding.patch",
);

function writeIfChanged(path, contents) {
  const bytes = Buffer.isBuffer(contents) ? contents : Buffer.from(contents);
  if (existsSync(path) && readFileSync(path).equals(bytes)) return;
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, bytes);
}

function applyBrandingPatch(frontendDir) {
  const git = (args) =>
    spawnSync("git", ["apply", ...args, brandingPatch], {
      cwd: frontendDir,
      encoding: "utf8",
    });
  // Source edits may move a patch's context (e.g. removing a toolbar action)
  // while retaining every branding change. Check the added lines themselves
  // before attempting to reapply; never overwrite a customized source file.
  const alreadyBranded = () => {
    const additions = new Map();
    let file = null;
    for (const line of readFileSync(brandingPatch, "utf8")
      .replace(/\r\n/g, "\n")
      .split("\n")) {
      if (line.startsWith("diff --git ")) file = null;
      else if (line.startsWith("+++ b/")) {
        file = line.slice(6);
        additions.set(file, []);
      } else if (file && line.startsWith("+") && line.slice(1).trim())
        additions.get(file).push(line.slice(1).trim());
    }
    return (
      additions.size > 0 &&
      [...additions].every(([file, lines]) => {
        const path = join(frontendDir, file);
        if (!existsSync(path)) return false;
        const present = new Set(
          readFileSync(path, "utf8")
            .split(/\r?\n/)
            .map((line) => line.trim()),
        );
        return lines.length > 0
          ? lines.every((line) => present.has(line))
          : git(["--reverse", "--check", `--include=${file}`]).status === 0;
      })
    );
  };
  const applied = git(["--reverse", "--check"]);
  if (applied.error) throw applied.error;
  if (applied.status === 0 || alreadyBranded()) return;
  // Upgrade the first branded checkout before checking the consolidated patch.
  // This preserves existing ignored doona worktrees when the icon size changes.
  for (const [file, selector, oldSize, size] of [
    ["src/ui/styles/shell-search.css", ".rp-brand img", 36, 52],
    ["src/ui/styles/cards-dashboard.css", ".rp-login-brand img", 56, 72],
  ]) {
    const path = join(frontendDir, file);
    if (!existsSync(path)) continue;
    const text = readFileSync(path, "utf8").replace(/\r\n/g, "\n");
    const previous = `${selector} {\n  width: ${oldSize}px;\n  height: ${oldSize}px;`;
    if (text.includes(previous))
      writeIfChanged(
        path,
        text.replace(
          previous,
          `${selector} {\n  width: ${size}px;\n  height: ${size}px;`,
        ),
      );
  }
  if (git(["--reverse", "--check"]).status === 0 || alreadyBranded()) return;
  const check = git(["--check"]);
  if (check.status !== 0) {
    throw new Error(
      `Cannot apply LemonVPN branding. Apply doona-lemonvpn-desktop.patch first and retain the branding changes.\n${check.stderr}`,
    );
  }
  const result = git([]);
  if (result.status !== 0)
    throw new Error(`Cannot apply LemonVPN branding:\n${result.stderr}`);
}

export function prepareBranding(frontendDir = join(repoRoot, "doona")) {
  applyBrandingPatch(frontendDir);
  const assets = new Map([
    ["logo.png", ["src/logo.png", "public/logo.png"]],
    ["icon-32.png", ["public/icons/icon-32.png"]],
    ["icon-192.png", ["public/icons/icon-192.png"]],
    ["icon-512.png", ["public/icons/icon-512.png"]],
    ["apple-touch-icon.png", ["public/icons/apple-touch-icon.png"]],
    ["maskable-512.png", ["public/icons/maskable-512.png"]],
  ]);
  for (const [source, destinations] of assets) {
    const bytes = readFileSync(join(brandingDir, source));
    for (const destination of destinations)
      writeIfChanged(join(frontendDir, destination), bytes);
  }
  // Old bookmarks/PWA caches can still request logo.svg. Keep that URL on the
  // approved raster artwork too; this wrapper is not a separate vector master.
  const png = readFileSync(join(brandingDir, "logo.png")).toString("base64");
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="512" height="512" viewBox="0 0 512 512"><image width="512" height="512" href="data:image/png;base64,${png}"/></svg>\n`;
  for (const destination of ["src/logo.svg", "public/logo.svg"])
    writeIfChanged(join(frontendDir, destination), svg);
  console.log("[branding] LemonVPN graphite/white assets synchronized");
}

if (
  process.argv[1] &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  try {
    prepareBranding();
  } catch (error) {
    console.error(`[branding] ${error.message}`);
    process.exitCode = 1;
  }
}
