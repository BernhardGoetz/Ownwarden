/**
 * Gegenproben zur öffentlichen Schnittstelle (index.ts) und zu readKdbx/writeKdbx:
 *
 *   - index.ts verspricht: „Alles hier läuft auch im Service Worker einer Browser-Erweiterung
 *     (keine Node-APIs).“ Geprüft wird jede Datei, die von index.ts aus (direkt oder über
 *     andere Dateien) importiert wird: keine Node-Module (node:…, fs, path …), kein Buffer,
 *     kein process, kein require, und als Pakete nur die erlaubten Bibliotheken.
 *   - writeKdbx verspricht „Verändert `vault` nicht“ – auch nicht die Schlüsselableitung, die
 *     createNewVault per Verweis übernimmt (sonst würde z. B. ein gemeinsam benutztes
 *     KDF-Objekt verändert).
 */
import { readFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { createNewVault, readKdbx, writeKdbx } from "./kdbx/index";
import { createVaultClock } from "./merge/clock";
import { createEntry, createGroup, setAttachment, setPasskey, setTags } from "./merge/vault-ops";
import type { KdfParams } from "./model";

const SRC = dirname(fileURLToPath(import.meta.url));
/** Pakete, die der Kern benutzen darf (package.json, alle laufen im Browser). */
const ALLOWED_PACKAGES = ["@noble/ciphers", "@noble/hashes", "hash-wasm", "@xmldom/xmldom"];
const NODE_BUILTINS = /^(node:|fs$|fs\/|path$|crypto$|zlib$|child_process$|buffer$|stream$|os$|url$|util$|readline$|http$|https$|net$|tls$)/;

/** Quelltext ohne Kommentare (damit erklärende Kommentare wie „anders als Buffer“ nicht stören). */
function withoutComments(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:"'`])\/\/.*$/gm, "$1");
}

/** Alle Dateien, die von `entry` aus erreichbar sind (relative Importe), mit ihren Paket-Importen. */
function reachableFiles(entry: string): Map<string, string[]> {
  const result = new Map<string, string[]>();
  const pending = [entry];
  while (pending.length > 0) {
    const file = pending.pop()!;
    if (result.has(file)) continue;
    const source = withoutComments(readFileSync(file, "utf8"));
    const specifiers = [...source.matchAll(/\b(?:import|export)\b[^'"`;]*?\bfrom\s*["']([^"']+)["']|\bimport\s*\(\s*["']([^"']+)["']\s*\)/g)].map(
      (match) => match[1] ?? match[2]!,
    );
    const packages: string[] = [];
    for (const specifier of specifiers) {
      if (specifier.startsWith(".")) pending.push(resolve(dirname(file), specifier.endsWith(".ts") ? specifier : `${specifier}.ts`));
      else packages.push(specifier);
    }
    result.set(file, packages);
  }
  return result;
}

describe("öffentliche Schnittstelle: läuft ohne Node-APIs (Service Worker)", () => {
  it("keine Node-Module, kein Buffer/process/require, nur erlaubte Pakete – in allen erreichbaren Dateien", () => {
    const files = reachableFiles(join(SRC, "index.ts"));
    expect(files.size).toBeGreaterThan(20); // Plausibilität: Der Import-Baum wurde wirklich verfolgt
    const problems: string[] = [];
    for (const [file, packages] of files) {
      const name = relative(SRC, file);
      if (name.startsWith("cli/") || name.includes(".test.") || name.includes("testing/")) problems.push(`${name}: gehört nicht in die Bibliothek`);
      for (const specifier of packages) {
        if (NODE_BUILTINS.test(specifier)) problems.push(`${name}: importiert ${specifier}`);
        else if (!ALLOWED_PACKAGES.some((allowed) => specifier === allowed || specifier.startsWith(`${allowed}/`))) problems.push(`${name}: Paket ${specifier}`);
      }
      const code = withoutComments(readFileSync(file, "utf8"));
      for (const pattern of [/\bBuffer\b/, /\bprocess\./, /\brequire\(/, /\b__dirname\b/]) {
        if (pattern.test(code)) problems.push(`${name}: benutzt ${pattern.source}`);
      }
    }
    expect(problems).toEqual([]);
  });
});

describe("writeKdbx verändert das Modell nicht", () => {
  it("weder den Tresor (tief verglichen) noch das an createNewVault übergebene KDF-Objekt", async () => {
    const kdf: KdfParams = { type: "argon2id", salt: new Uint8Array(32), parallelism: 1, memoryBytes: 1 << 20, iterations: 2, version: 0x13 };
    const vault = createNewVault({ name: "Unverändert", now: Date.now(), kdf, allowWeakKdf: true });
    const clock = createVaultClock(vault);
    const group = createGroup(vault, vault.root.uuid, "Bank", clock);
    const entry = createEntry(vault, group.uuid, { Title: "Giro", Password: "pw", Notes: "Zeile 1\r\nZeile 2", PIN: { value: "1", protected: true } }, clock);
    setAttachment(vault, entry.uuid, "scan.bin", Uint8Array.from([0, 1, 255]), {}, clock);
    setPasskey(vault, entry.uuid, { KPEX_PASSKEY_USERNAME: "u", KPEX_PASSKEY_PRIVATE_KEY_PEM: "-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----" }, clock);
    setTags(vault, entry.uuid, ["b", "a"], clock);
    vault.root.tags = ["kdbx41"]; // erzwingt das Anheben auf 4.1 beim Schreiben

    const before = structuredClone(vault);
    const file = await writeKdbx(vault, { password: "pw" });
    expect(vault).toEqual(before);
    expect(kdf.salt).toEqual(new Uint8Array(32));

    const read = await readKdbx(file, { password: "pw" });
    const readBefore = structuredClone(read);
    await writeKdbx(read, { password: "pw" });
    expect(read).toEqual(readBefore);
  });
});
