/**
 * Test-Hilfen für die Tests unter test/interop/ und test/e2e/: KDBX-Dateien über die
 * öffentliche Schnittstelle (readKdbx/writeKdbx) lesen und schreiben, und KeePassXC-Exporte
 * auswerten.
 *
 * Nur für Tests: benutzt Node-APIs (fs).
 */
import { readFileSync, writeFileSync } from "node:fs";
import { identityStream } from "../fixtures/xml/fixtures";
import { readKdbx, writeKdbx } from "../../src/kdbx/index";
import { decryptContainer } from "../../src/kdbx/container";
import { parseVaultXml } from "../../src/kdbx/xml";
import type { Entry, Group, KdfParams, Vault } from "../../src/model";
import { runKpxcOk } from "./keepassxc";

/**
 * Schnelle Schlüsselableitung NUR für Tests (Argon2id, 1 MiB, 2 Durchläufe). Echte
 * Datenbanken bekommen die Standardwerte aus defaultKdbxSettings().
 */
export const TEST_KDF: KdfParams = { type: "argon2id", salt: new Uint8Array(32), parallelism: 1, memoryBytes: 1 << 20, iterations: 2, version: 0x13 };

/** Meldungen, mit denen KeePassXC Probleme beim Lesen der XML anzeigt (wie in src/kdbx/xml.interop.test.ts). */
export const KPXC_XML_WARNING = /KdbxXmlReader|skip element|Invalid|Unmapped|unused key|Duplicate|Missing/i;

/** Liest eine KDBX-Datei von der Platte (readKdbx). */
export async function readKdbxFile(path: string, password: string): Promise<Vault> {
  return readKdbx(new Uint8Array(readFileSync(path)), { password });
}

/** Schreibt eine KDBX-Datei auf die Platte (writeKdbx). */
export async function writeKdbxFile(vault: Vault, path: string, password: string): Promise<void> {
  writeFileSync(path, await writeKdbx(vault, { password }));
}

/**
 * Was KeePassXC in einer Datei sieht: `keepassxc-cli export -f xml`, eingelesen ins Modell
 * (dazu der XML-Text und die Fehlerausgabe, z. B. für Warnungen).
 * Im Export stehen geschützte Werte im Klartext (ProtectInMemory) und Anhänge nur als Verweis
 * in den Binär-Pool der Datei – den liefert decryptContainer.
 */
export async function kpxcExportedVault(path: string, password: string): Promise<{ vault: Vault; xml: string; stderr: string }> {
  const { stdout: xml, stderr } = await runKpxcOk(["export", "-q", "-f", "xml", path], `${password}\n`);
  const payload = await decryptContainer(new Uint8Array(readFileSync(path)), { password });
  return { vault: parseVaultXml(new TextEncoder().encode(xml), payload.binaries, identityStream(), payload.settings), xml, stderr };
}

/** Alle Einträge (ohne Verlauf) mit ihrem Pfad "Gruppe/Untergruppe/Titel" (ohne Wurzelgruppe). */
export function entriesWithPaths(vault: Vault): { path: string; entry: Entry; group: Group }[] {
  const result: { path: string; entry: Entry; group: Group }[] = [];
  const walk = (group: Group, prefix: string): void => {
    for (const entry of group.entries) result.push({ path: prefix + (entry.strings.get("Title")?.value ?? ""), entry, group });
    for (const child of group.groups) walk(child, `${prefix}${child.name}/`);
  };
  walk(vault.root, "");
  return result;
}

/** Der Eintrag mit genau diesem Pfad (siehe entriesWithPaths); wirft, wenn es ihn nicht gibt. */
export function entryAt(vault: Vault, path: string): { entry: Entry; group: Group } {
  const found = entriesWithPaths(vault).filter((item) => item.path === path);
  if (found.length !== 1) throw new Error(`Eintrag "${path}" ${found.length}-mal gefunden`);
  return found[0]!;
}

/** Wartet bis in die nächste Sekunde: KDBX- und KeePassXC-Zeiten sind nur sekundengenau. */
export function waitForNextSecond(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 1100));
}
