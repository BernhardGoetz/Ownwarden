/**
 * Zusammenspiel mit KeePassXC (Referenzprogramm). Wird übersprungen, wenn `keepassxc-cli`
 * nicht installiert ist.
 *
 *   KeePassXC -> Ownwarden: KeePassXC legt eine Datei an, Ownwarden entschlüsselt sie.
 *   Ownwarden -> KeePassXC: Ownwarden verschlüsselt den Inhalt neu (verschiedene
 *                           Einstellungen), KeePassXC muss die Datei öffnen können.
 */
import { randomBytes } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  addKpxcEntry,
  createKpxcDb,
  createTmpDir,
  exportKpxcAttachment,
  hasKeepassxc,
  importKpxcAttachment,
  kpxcDbInfo,
  removeTmpDir,
  runKpxcOk,
  showKpxcEntry,
} from "../../test/helpers/keepassxc";
import type { DecryptedPayload, InnerStreamCipher } from "../contracts";
import type { KdbxSettings } from "../model";
import { utf8Decode, utf8Encode } from "./bytes";
import { decryptContainer, encryptContainer } from "./container";
import { parseOuterHeader } from "./header";
import { createInnerStream, newInnerStreamKey } from "./inner-stream";
import { parseVariantDictionary, serializeVariantDictionary } from "./variant-dictionary";

const code = (c: string) => expect.objectContaining({ code: c });

const DB_PASSWORD = "Interop-Test-Passwort-äöü";
const ENTRY = "Mein Eintrag";
const ENTRY_USER = "alice";
const ENTRY_PASSWORD = "Eintrags-Geheimnis-42";
const ATTACHMENT_NAME = "notiz.txt";
const ATTACHMENT = "Anhang-Inhalt äöü\n";

const PROTECTED_VALUE = /<Value Protected="True">([^<]*)<\/Value>/g;

/** Alle geschützten Werte der XML in Dokumentreihenfolge mit EINEM Strom entschlüsseln. */
function decryptProtectedValues(xml: Uint8Array, stream: InnerStreamCipher): string[] {
  return [...utf8Decode(xml).matchAll(PROTECTED_VALUE)].map((m) =>
    utf8Decode(stream.process(Uint8Array.from(Buffer.from(m[1]!, "base64")))),
  );
}

/** Geschützte Werte von einem inneren Strom auf einen anderen umschlüsseln. */
function reencryptProtectedValues(xml: Uint8Array, from: InnerStreamCipher, to: InnerStreamCipher): Uint8Array {
  const text = utf8Decode(xml).replace(PROTECTED_VALUE, (_match, base64: string) => {
    const plain = from.process(Uint8Array.from(Buffer.from(base64, "base64")));
    return `<Value Protected="True">${Buffer.from(to.process(plain)).toString("base64")}</Value>`;
  });
  return utf8Encode(text);
}

describe.skipIf(!hasKeepassxc())("KeePassXC-Interop: Container", () => {
  let dir: string;
  let kpxcFile: Uint8Array;
  let kpxcPayload: DecryptedPayload;

  beforeAll(async () => {
    dir = createTmpDir("kdbx-container");
    const dbPath = join(dir, "keepassxc.kdbx");
    await createKpxcDb(dbPath, DB_PASSWORD, { decryptionTimeMs: 100 });
    await addKpxcEntry(dbPath, DB_PASSWORD, ENTRY, {
      username: ENTRY_USER,
      url: "https://example.org",
      password: ENTRY_PASSWORD,
    });
    const attachmentPath = join(dir, "anhang.txt");
    writeFileSync(attachmentPath, ATTACHMENT);
    await importKpxcAttachment(dbPath, DB_PASSWORD, ENTRY, ATTACHMENT_NAME, attachmentPath);
    kpxcFile = new Uint8Array(readFileSync(dbPath));
    kpxcPayload = await decryptContainer(kpxcFile, { password: DB_PASSWORD });
  });

  afterAll(() => {
    if (dir) removeTmpDir(dir);
  });

  describe("KeePassXC -> Ownwarden", () => {
    it("liest Einstellungen, inneren Header, Anhänge und XML", () => {
      expect(kpxcPayload.settings).toMatchObject({ versionMinor: 0, cipher: "aes256", compression: true });
      expect(kpxcPayload.settings.kdf.type).toBe("aes");
      expect(kpxcPayload.innerStreamId).toBe("chacha20");
      expect(kpxcPayload.innerStreamKey.length).toBe(64);
      expect(kpxcPayload.binaries).toHaveLength(1);
      expect(utf8Decode(kpxcPayload.binaries[0]!.data)).toBe(ATTACHMENT);
      expect(kpxcPayload.binaries[0]!.protected).toBe(true); // KeePassXC setzt das Flag immer

      const xml = utf8Decode(kpxcPayload.xml);
      expect(xml).toContain("<KeePassFile>");
      expect(xml).toContain(`<Value>${ENTRY}</Value>`);
      expect(xml).toContain(`<Value>${ENTRY_USER}</Value>`);
      expect(xml).not.toContain(ENTRY_PASSWORD); // geschützt, also nicht im Klartext
    });

    it("entschlüsselt alle geschützten Werte mit dem fortlaufenden inneren Strom", () => {
      // Eintrag + Verlaufseintrag (attachment-import legt einen an) enthalten das Passwort.
      const stream = createInnerStream(kpxcPayload.innerStreamId, kpxcPayload.innerStreamKey);
      const values = decryptProtectedValues(kpxcPayload.xml, stream);
      expect(values.length).toBeGreaterThanOrEqual(2);
      expect(new Set(values)).toEqual(new Set([ENTRY_PASSWORD]));
    });

    it("falsches Passwort -> InvalidCredentials", async () => {
      await expect(decryptContainer(kpxcFile, { password: "falsch" })).rejects.toThrow(code("InvalidCredentials"));
    });

    it("ein gekipptes Byte im Blockbereich -> Corrupt", async () => {
      const headerLength = parseOuterHeader(kpxcFile).headerBytes.length;
      for (const index of [headerLength + 64 + 36 + 3, kpxcFile.length - 36 - 1]) {
        const tampered = kpxcFile.slice();
        tampered[index]! ^= 0x80;
        await expect(decryptContainer(tampered, { password: DB_PASSWORD })).rejects.toThrow(code("Corrupt"));
      }
    });

    it("lehnt die KDBX-3.1-Datei von `keepassxc-cli db-create` mit UnsupportedVersion ab", async () => {
      const path = join(dir, "kdbx31.kdbx");
      await runKpxcOk(["db-create", "-q", "-p", "-t", "100", path], `${DB_PASSWORD}\n${DB_PASSWORD}\n`);
      await expect(decryptContainer(new Uint8Array(readFileSync(path)), { password: DB_PASSWORD })).rejects.toThrow(
        code("UnsupportedVersion"),
      );
    });

    it("liest und schreibt mehrere HMAC-Blöcke (2,5 MiB Zufallsanhang) wie KeePassXC", async () => {
      const path = join(dir, "mehrblock.kdbx");
      const randomData = new Uint8Array(randomBytes(2_500_000)); // unkomprimierbar -> 3 Datenblöcke
      const randomPath = join(dir, "zufall.bin");
      writeFileSync(randomPath, randomData);
      await createKpxcDb(path, DB_PASSWORD);
      await addKpxcEntry(path, DB_PASSWORD, "Gross");
      await importKpxcAttachment(path, DB_PASSWORD, "Gross", "zufall.bin", randomPath);
      const file = new Uint8Array(readFileSync(path));

      // KeePassXC hat wirklich mehrere volle 1-MiB-Blöcke geschrieben.
      const sizes: number[] = [];
      let pos = parseOuterHeader(file).headerBytes.length + 64;
      for (;;) {
        const size = new DataView(file.buffer, file.byteOffset + pos + 32, 4).getInt32(0, true);
        sizes.push(size);
        pos += 36 + size;
        if (size === 0) break;
      }
      expect(sizes.length).toBeGreaterThanOrEqual(4);
      expect(sizes.slice(0, 2)).toEqual([1024 * 1024, 1024 * 1024]);

      const payload = await decryptContainer(file, { password: DB_PASSWORD });
      expect(payload.binaries).toHaveLength(1);
      expect(Buffer.from(payload.binaries[0]!.data).equals(Buffer.from(randomData))).toBe(true);

      // Rückweg: Ownwarden schreibt (ChaCha20), KeePassXC liest den Anhang byte-genau.
      const ownPath = join(dir, "mehrblock-ownwarden.kdbx");
      const settings: KdbxSettings = { ...payload.settings, cipher: "chacha20" };
      writeFileSync(ownPath, await encryptContainer({ ...payload, settings }, { password: DB_PASSWORD }));
      const exported = await exportKpxcAttachment(ownPath, DB_PASSWORD, "Gross", "zufall.bin");
      expect(Buffer.from(exported).equals(Buffer.from(randomData))).toBe(true);
    });

    it("liest eine KDBX-4.1-Datei von KeePassXC", async () => {
      const path = join(dir, "kdbx41.kdbx");
      await createKpxcDb(path, DB_PASSWORD, { version: "4.1" });
      const payload = await decryptContainer(new Uint8Array(readFileSync(path)), { password: DB_PASSWORD });
      expect(payload.settings.versionMinor).toBe(1);
      expect(utf8Decode(payload.xml)).toContain("<Tags>kdbx41</Tags>");
    });
  });

  describe("Ownwarden -> KeePassXC", () => {
    const smallArgon2 = { salt: new Uint8Array(32), parallelism: 2, memoryBytes: 1024 * 1024, iterations: 2, version: 0x13 };
    const variants: { name: string; settings: (s: KdbxSettings) => KdbxSettings; cipher: string; kdf: RegExp }[] = [
      { name: "unveränderte Einstellungen", settings: (s) => s, cipher: "AES 256-bit", kdf: /^AES \(\d+ rounds\)$/ },
      {
        name: "ChaCha20 + Argon2id",
        settings: (s) => ({ ...s, cipher: "chacha20", kdf: { type: "argon2id", ...smallArgon2 } }),
        cipher: "ChaCha20 256-bit",
        kdf: /^Argon2id \(2 rounds, 1024 KB\)$/,
      },
      {
        name: "AES-256 + Argon2d",
        settings: (s) => ({ ...s, kdf: { type: "argon2d", ...smallArgon2 } }),
        cipher: "AES 256-bit",
        kdf: /^Argon2d \(2 rounds, 1024 KB\)$/,
      },
      {
        name: "AES-KDF mit wenigen Runden",
        settings: (s) => ({ ...s, kdf: { type: "aes", seed: new Uint8Array(32), rounds: 1000 } }),
        cipher: "AES 256-bit",
        kdf: /^AES \(1000 rounds\)$/,
      },
      {
        name: "ohne Kompression",
        settings: (s) => ({ ...s, compression: false, kdf: { type: "aes", seed: new Uint8Array(32), rounds: 1000 } }),
        cipher: "AES 256-bit",
        kdf: /^AES \(1000 rounds\)$/,
      },
      {
        name: "ChaCha20 ohne Kompression, Header KDBX 4.1",
        settings: (s) => ({ ...s, versionMinor: 1, cipher: "chacha20", compression: false }),
        cipher: "ChaCha20 256-bit",
        kdf: /^AES \(\d+ rounds\)$/,
      },
    ];

    it.each(variants)("KeePassXC öffnet die Datei: $name", async ({ name, settings, cipher, kdf }) => {
      const payload = { ...kpxcPayload, settings: settings(kpxcPayload.settings) };
      const file = await encryptContainer(payload, { password: DB_PASSWORD });

      // frische Seeds: nichts aus der Originaldatei wiederverwendet
      const original = parseOuterHeader(kpxcFile).header;
      const written = parseOuterHeader(file).header;
      expect(written.masterSeed).not.toEqual(original.masterSeed);
      expect(written.encryptionIv).not.toEqual(original.encryptionIv);

      const path = join(dir, `ownwarden-${name.replace(/\W+/g, "-")}.kdbx`);
      writeFileSync(path, file);
      const shown = await showKpxcEntry(path, DB_PASSWORD, ENTRY, { showProtected: true, showAttachments: true });
      expect(shown).toContain(`UserName: ${ENTRY_USER}`);
      expect(shown).toContain(`Password: ${ENTRY_PASSWORD}`);
      expect(shown).toContain(ATTACHMENT_NAME);
      expect(utf8Decode(await exportKpxcAttachment(path, DB_PASSWORD, ENTRY, ATTACHMENT_NAME))).toBe(ATTACHMENT);

      const info = await kpxcDbInfo(path, DB_PASSWORD);
      expect(info.Cipher).toBe(cipher);
      expect(info.KDF).toMatch(kdf);
    });

    it("KeePassXC liest den Salsa20-Innenstrom", async () => {
      const salsaKey = newInnerStreamKey();
      const xml = reencryptProtectedValues(
        kpxcPayload.xml,
        createInnerStream("chacha20", kpxcPayload.innerStreamKey),
        createInnerStream("salsa20", salsaKey),
      );
      const payload = { ...kpxcPayload, innerStreamId: "salsa20" as const, innerStreamKey: salsaKey, xml };
      const path = join(dir, "ownwarden-salsa20.kdbx");
      writeFileSync(path, await encryptContainer(payload, { password: DB_PASSWORD }));
      const shown = await showKpxcEntry(path, DB_PASSWORD, ENTRY, { attributes: ["Password"] });
      expect(shown.trim()).toBe(ENTRY_PASSWORD);
    });

    it("KeePassXC öffnet Passwort + Schlüsseldatei (32-Byte-Datei = Rohschlüssel)", async () => {
      const keyFileKey = Uint8Array.from({ length: 32 }, (_, i) => (i * 37 + 11) & 0xff);
      const keyFile = join(dir, "schluessel.key");
      writeFileSync(keyFile, keyFileKey);
      const path = join(dir, "ownwarden-keyfile.kdbx");
      writeFileSync(path, await encryptContainer(kpxcPayload, { password: DB_PASSWORD, keyFileKey }));
      const shown = await showKpxcEntry(path, { password: DB_PASSWORD, keyFile }, ENTRY, { attributes: ["UserName"] });
      expect(shown.trim()).toBe(ENTRY_USER);
    });

    it("KeePassXC öffnet eine Datei nur mit Schlüsseldatei (ohne Passwort)", async () => {
      const keyFileKey = Uint8Array.from({ length: 32 }, (_, i) => (i * 53 + 7) & 0xff);
      const keyFile = join(dir, "nur-schluessel.key");
      writeFileSync(keyFile, keyFileKey);
      const path = join(dir, "ownwarden-keyfile-only.kdbx");
      writeFileSync(path, await encryptContainer(kpxcPayload, { keyFileKey }));
      const shown = await showKpxcEntry(path, { keyFile }, ENTRY, { attributes: ["UserName"] });
      expect(shown.trim()).toBe(ENTRY_USER);
    });

    // Gegenprobe der KDF in Rückrichtung: KeePassXC würfelt beim Speichern einen neuen Salt
    // aus und rechnet die KDF selbst; Ownwarden muss genau dasselbe Ergebnis erhalten.
    const resaveVariants: { name: string; settings: Partial<KdbxSettings> }[] = [
      { name: "Argon2d + AES-256", settings: { kdf: { type: "argon2d", ...smallArgon2 } } },
      { name: "Argon2id P=1 + ChaCha20", settings: { cipher: "chacha20", kdf: { type: "argon2id", ...smallArgon2, parallelism: 1 } } },
      {
        name: "AES-KDF ohne Kompression",
        settings: { compression: false, kdf: { type: "aes", seed: new Uint8Array(32), rounds: 1000 } },
      },
    ];

    it.each(resaveVariants)("KeePassXC rechnet die KDF selbst nach: $name", async ({ name, settings: changes }) => {
      const settings: KdbxSettings = { ...kpxcPayload.settings, ...changes };
      const path = join(dir, `ownwarden-resave-${name.replace(/\W+/g, "-")}.kdbx`);
      writeFileSync(path, await encryptContainer({ ...kpxcPayload, settings }, { password: DB_PASSWORD }));
      const written = parseOuterHeader(new Uint8Array(readFileSync(path))).header;

      await addKpxcEntry(path, DB_PASSWORD, "Nachgerechnet", { password: "nachgerechnet-geheim" });
      const resavedFile = new Uint8Array(readFileSync(path));
      const resaved = await decryptContainer(resavedFile, { password: DB_PASSWORD });

      // Einstellungen bleiben, aber KeePassXC hat neuen Salt und Master-Seed gewählt.
      const { salt: _s, seed: _d, ...expectedKdf } = settings.kdf as Record<string, unknown>;
      expect(resaved.settings).toMatchObject({ cipher: settings.cipher, compression: settings.compression });
      expect(resaved.settings.kdf).toMatchObject(expectedKdf);
      const saltOf = (k: KdbxSettings["kdf"]) => (k.type === "aes" ? k.seed : k.salt);
      expect(saltOf(resaved.settings.kdf)).not.toEqual(saltOf(written.kdf));
      expect(parseOuterHeader(resavedFile).header.masterSeed).not.toEqual(written.masterSeed);

      const values = decryptProtectedValues(resaved.xml, createInnerStream(resaved.innerStreamId, resaved.innerStreamKey));
      expect(values).toContain("nachgerechnet-geheim");
      expect(values).toContain(ENTRY_PASSWORD);
    });

    it("KeePassXC speichert eine Ownwarden-Datei um; Einstellungen und PublicCustomData bleiben", async () => {
      const publicCustomData = serializeVariantDictionary(new Map([["Ownwarden.Probe", { type: "string", value: "öffentlich" }]]));
      const settings: KdbxSettings = {
        ...kpxcPayload.settings,
        cipher: "chacha20",
        kdf: { type: "argon2id", ...smallArgon2 },
        publicCustomData,
      };
      const path = join(dir, "ownwarden-resaved.kdbx");
      writeFileSync(path, await encryptContainer({ ...kpxcPayload, settings }, { password: DB_PASSWORD }));

      // KeePassXC ändert die Datei und schreibt sie komplett neu.
      await addKpxcEntry(path, DB_PASSWORD, "Von KeePassXC", { username: "bob", password: "bob-geheim" });
      const resaved = await decryptContainer(new Uint8Array(readFileSync(path)), { password: DB_PASSWORD });

      expect(resaved.settings.cipher).toBe("chacha20");
      expect(resaved.settings.kdf).toMatchObject({ type: "argon2id", memoryBytes: 1024 * 1024, iterations: 2, parallelism: 2 });
      expect(parseVariantDictionary(resaved.settings.publicCustomData!).get("Ownwarden.Probe")).toEqual({
        type: "string",
        value: "öffentlich",
      });
      expect(utf8Decode(resaved.xml)).toContain("<Value>Von KeePassXC</Value>");
      const values = decryptProtectedValues(resaved.xml, createInnerStream(resaved.innerStreamId, resaved.innerStreamKey));
      expect(values).toContain("bob-geheim");
      expect(values).toContain(ENTRY_PASSWORD);
    });
  });
});
