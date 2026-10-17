/**
 * Strenger Modus der Test-Hilfen (Review xc-8): Mit OWNWARDEN_REQUIRE_TOOLS=1 ist ein fehlendes
 * keepassxc-cli bzw. PHP ein Fehler – sonst werden die betroffenen Tests nur übersprungen, und
 * `npm test` endet trotzdem mit Exit-Code 0.
 */
import { spawn } from "node:child_process";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { CORE_DIR, REQUIRE_TOOLS_ENV, toolAvailable } from "./keepassxc";

describe("toolAvailable", () => {
  it("ohne strengen Modus: fehlendes Werkzeug -> false (Test wird übersprungen)", () => {
    expect(toolAvailable(false, "KeePassXC", {})).toBe(false);
    expect(toolAvailable(true, "KeePassXC", { [REQUIRE_TOOLS_ENV]: "1" })).toBe(true);
  });

  it("strenger Modus: fehlendes Werkzeug -> Fehler mit Namen des Werkzeugs", () => {
    expect(() => toolAvailable(false, "KeePassXC", { [REQUIRE_TOOLS_ENV]: "1" })).toThrow(/KeePassXC fehlt, aber OWNWARDEN_REQUIRE_TOOLS=1/);
  });

  it("ganzer Lauf: ohne keepassxc-cli übersprungen (Exit 0), im strengen Modus fehlgeschlagen (Exit ≠ 0)", async () => {
    const runInterop = (extra: Record<string, string>) =>
      new Promise<number>((resolvePromise, reject) => {
        const env: NodeJS.ProcessEnv = { ...process.env, KEEPASSXC_CLI: join(CORE_DIR, "gibt-es-nicht", "keepassxc-cli"), ...extra };
        for (const name of Object.keys(env)) if (name.startsWith("VITEST")) delete env[name];
        if (!(REQUIRE_TOOLS_ENV in extra)) delete env[REQUIRE_TOOLS_ENV];
        const child = spawn(join(CORE_DIR, "node_modules", ".bin", "vitest"), ["run", "src/kdbx/container.interop.test.ts"], { cwd: CORE_DIR, env, stdio: "ignore" });
        child.on("error", reject);
        child.on("close", (code) => resolvePromise(code ?? -1));
      });
    expect(await runInterop({})).toBe(0);
    expect(await runInterop({ [REQUIRE_TOOLS_ENV]: "1" })).not.toBe(0);
  }, 60_000);
});
