// Starts a real pandod with browser access, imports a small git repository into it, clones it
// and locks a file, so the tests exercise the console against the actual server.

import { execFileSync, spawn } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { connect } from "node:net";
import { join, resolve } from "node:path";

const bin = resolve(process.env.PANDO_BIN ?? "../target/release");
export const PORT = 7611;
export const SERVER = `http://127.0.0.1:${PORT}`;
/** A second server that hosts many repositories (platform phase 1). */
export const HOSTING_PORT = 7613;
export const HOSTING = `http://127.0.0.1:${HOSTING_PORT}`;

function git(cwd: string, ...args: string[]) {
  execFileSync("git", ["-c", "user.name=Ada", "-c", "user.email=ada@example.com", "-c", "commit.gpgsign=false", ...args], { cwd, stdio: "pipe" });
}

/** Resolves once something accepts connections on the port (pandod is up). */
async function up(port: number) {
  for (let i = 0; i < 100; i++) {
    const ok = await new Promise<boolean>((done) => {
      const s = connect(port, "127.0.0.1", () => (s.end(), done(true)));
      s.on("error", () => done(false));
    });
    if (ok) return;
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`pandod did not start on port ${port}`);
}

export default async function setup() {
  const dir = mkdtempSync(join(tmpdir(), "pando-console-e2e-"));
  const src = join(dir, "src");
  mkdirSync(join(src, "services/billing"), { recursive: true });
  writeFileSync(join(src, "README.md"), "# Orchard\n\nA small repository for the console's end-to-end tests.\n");
  writeFileSync(join(src, "services/billing/tax.rs"), "pub const RATE_BPS: u32 = 1900;\n\npub fn tax(cents: u64) -> u64 {\n    cents * RATE_BPS as u64 / 10_000\n}\n");
  writeFileSync(join(src, "generated.rs"), Array.from({ length: 50_000 }, (_, i) => `pub const ITEM_${i}: u32 = ${i};`).join("\n") + "\n");
  writeFileSync(join(src, "design.psd"), Buffer.from([0x38, 0x42, 0x50, 0x53, 0, 1, 2, 3]));
  git(src, "init", "-q", "-b", "main");
  git(src, "add", "-A");
  git(src, "commit", "-qm", "Start the orchard");
  writeFileSync(join(src, "services/billing/tax.rs"), "pub const RATE_BPS: u32 = 2000;\n\npub fn tax(cents: u64) -> u64 {\n    cents * RATE_BPS as u64 / 10_000\n}\n");
  git(src, "commit", "-qam", "Raise the tax rate to 20%");

  const server = spawn(join(bin, "pandod"), ["server", "--listen", `127.0.0.1:${PORT}`, "--metadata", `sqlite://${join(dir, "meta.db")}`, "--web-origins", "http://127.0.0.1:4173"], {
    stdio: ["ignore", "ignore", "inherit"],
  });
  try {
    await up(PORT);
    const run = (args: string[], cwd?: string) => execFileSync(join(bin, "pando"), args, { cwd, stdio: ["ignore", "pipe", "pipe"], timeout: 30_000 });
    run(["import-git", src, "--server", SERVER]);
    const clone = join(dir, "clone");
    run(["clone", SERVER, clone]);
    run(["lock", "design.psd"], clone);
  } catch (e) {
    server.kill();
    throw e;
  }

  const hosting = spawn(
    join(bin, "pandod"),
    ["server", "--listen", `127.0.0.1:${HOSTING_PORT}`, "--metadata", "memory", "--platform", `sqlite://${join(dir, "platform.db")}`, "--repos-metadata", `sqlite://${join(dir, "repos")}/{repo}.db`, "--platform-admins", "anonymous", "--webhook-allow-private", "--web-origins", "http://127.0.0.1:4173"],
    { stdio: ["ignore", "ignore", "inherit"] },
  );
  try {
    await up(HOSTING_PORT);
    const run = (args: string[], cwd?: string) => execFileSync(join(bin, "pando"), args, { cwd, stdio: ["ignore", "pipe", "pipe"], timeout: 30_000 });
    run(["repo", "create", "lumen/fleet", "--description", "The product monorepo", "--server", HOSTING]);
    run(["repo", "create", "lumen/web", "--description", "The storefront", "--server", HOSTING]);
    run(["import-git", src, "--server", `${HOSTING}/lumen/fleet`]);
    // A change request on a branch, for the review screens.
    const fleet = join(dir, "fleet");
    run(["clone", `${HOSTING}/lumen/fleet`, fleet]);
    run(["checkout", "-b", "lower-rate"], fleet);
    const tax = join(fleet, "services/billing/tax.rs");
    writeFileSync(tax, readFileSync(tax, "utf8").replace(/RATE_BPS: u32 = \d+/, "RATE_BPS: u32 = 1700"));
    run(["commit", "-m", "Lower the tax rate"], fleet);
    run(["land"], fleet);
    run(["cr", "create", "--title", "Lower the tax rate to 17%", "--body", "Matches the new regulation."], fleet);
    // A branch with no change request yet, for opening one in the console.
    run(["checkout", "main"], fleet);
    run(["checkout", "-b", "readme"], fleet);
    writeFileSync(join(fleet, "README.md"), "# Fleet\n\nThe product monorepo.\n");
    run(["commit", "-m", "Add a README"], fleet);
    run(["land"], fleet);
  } catch (e) {
    server.kill();
    hosting.kill();
    throw e;
  }

  return () => {
    server.kill();
    hosting.kill();
  };
}
