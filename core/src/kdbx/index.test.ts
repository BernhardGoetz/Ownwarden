/**
 * readKdbx / writeKdbx / createNewVault: das Zusammenspiel der KDBX-Bausteine ohne KeePassXC.
 * (Dass KeePassXC die Dateien öffnet, prüfen die Tests unter test/interop/.)
 */
import { describe, expect, it } from "vitest";
import { KdbxError } from "../contracts";
import { NULL_UUID, type KdfParams, type Vault } from "../model";
import { createVaultClock } from "../merge/clock";
import { createEntry, createGroup, setAttachment, setPasskey } from "../merge/vault-ops";
import { createKdbxCodec } from "../sync/kdbx-codec";
import { canonicalVault } from "../sync/vault-equal";
import { createNewVault, DEFAULT_ROOT_GROUP_NAME, readKdbx, writeKdbx } from "./index";

/** Schnelle Schlüsselableitung NUR für Tests. */
const TEST_KDF: KdfParams = { type: "argon2id", salt: new Uint8Array(32), parallelism: 1, memoryBytes: 1 << 20, iterations: 2, version: 0x13 };
const CREDENTIALS = { password: "Index-Test-äöü" };
const NOW = Date.UTC(2026, 9, 16, 8, 30, 15, 789);

/** Modell ohne `settings` (der KDF-Salt ist nach jedem Speichern neu). */
function content(vault: Vault): Omit<Vault, "settings"> {
  const { settings: _settings, ...rest } = vault;
  return rest;
}

/**
 * Vergleichbare Form (sync/vault-equal.ts): Zeiten in ganzen Sekunden. Nötig, weil die Uhr
 * beim Bearbeiten Millisekunden vergibt, die Datei aber nur Sekunden speichert.
 */
const comparable = (vault: Vault) => canonicalVault(vault);

function sampleVault(): Vault {
  const vault = createNewVault({ name: "Testtresor", now: NOW, kdf: TEST_KDF, allowWeakKdf: true });
  const clock = createVaultClock(vault, () => NOW + 5000);
  const group = createGroup(vault, vault.root.uuid, "Bank", clock);
  const entry = createEntry(vault, group.uuid, { Title: "Giro", UserName: "bob", Password: "geheim", PIN: { value: "1234", protected: true } }, clock);
  setAttachment(vault, entry.uuid, "scan.bin", Uint8Array.from([0, 1, 2, 255, 254]), {}, clock);
  setPasskey(vault, entry.uuid, { KPEX_PASSKEY_USERNAME: "bob", KPEX_PASSKEY_PRIVATE_KEY_PEM: "-----BEGIN PRIVATE KEY-----\nAAA\n-----END PRIVATE KEY-----" }, clock);
  return vault;
}

describe("createNewVault", () => {
  it("legt eine leere Datenbank mit KeePassXC-Standardwerten an", () => {
    const vault = createNewVault({ name: "Mein Tresor", now: NOW });
    const second = Math.floor(NOW / 1000) * 1000;

    expect(vault.meta.databaseName).toBe("Mein Tresor");
    expect(vault.root.name).toBe("Mein Tresor");
    expect(vault.root.entries).toEqual([]);
    expect(vault.root.groups).toEqual([]);
    expect(vault.meta.recycleBinEnabled).toBe(true);
    expect(vault.meta.recycleBinUuid).toBe(NULL_UUID);
    expect(vault.meta.historyMaxItems).toBe(10);
    expect(vault.meta.historyMaxSize).toBe(6 * 1024 * 1024);
    expect(vault.meta.databaseNameChanged).toBe(second);
    expect(vault.root.times.creation).toBe(second);
    expect(vault.settings).toMatchObject({ versionMinor: 0, cipher: "aes256", compression: true });
    expect(vault.settings.kdf).toMatchObject({ type: "argon2id", memoryBytes: 64 * 1024 * 1024, iterations: 3, parallelism: 2 });
    expect(vault.deletedObjects).toEqual([]);
  });

  it("ohne Namen heißt die Wurzelgruppe „Ownwarden“; jede Datenbank hat eine eigene Wurzel-UUID", () => {
    const a = createNewVault({ name: "", now: NOW });
    const b = createNewVault({ name: "", now: NOW });
    expect(a.root.name).toBe(DEFAULT_ROOT_GROUP_NAME);
    expect(a.root.uuid).not.toBe(b.root.uuid);
    expect(atob(a.root.uuid)).toHaveLength(16);
  });

  it("übernimmt eine eigene Schlüsselableitung, lehnt ungültige ab", () => {
    expect(createNewVault({ name: "x", now: NOW, kdf: TEST_KDF, allowWeakKdf: true }).settings.kdf).toEqual(TEST_KDF);
    expect(() => createNewVault({ name: "x", now: NOW, kdf: { ...TEST_KDF, memoryBytes: 1 }, allowWeakKdf: true })).toThrow(KdbxError);
  });

  it("lehnt eine Schlüsselableitung unter der Mindeststärke ab, außer ausdrücklich erlaubt (Sicherheitsaudit crypto-2)", () => {
    const weak: KdfParams[] = [
      TEST_KDF,
      { type: "aes", seed: new Uint8Array(32), rounds: 1 },
      { ...TEST_KDF, memoryBytes: 8 * 1024, iterations: 1 },
    ];
    for (const kdf of weak) {
      expect(() => createNewVault({ name: "x", now: NOW, kdf }), kdf.type).toThrow(RangeError);
      expect(() => createNewVault({ name: "x", now: NOW, kdf }), kdf.type).toThrow(/Mindeststärke/);
      expect(createNewVault({ name: "x", now: NOW, kdf, allowWeakKdf: true }).settings.kdf).toBe(kdf);
    }
    const owaspMinimum: KdfParams = { ...TEST_KDF, memoryBytes: 19 * 1024 * 1024, iterations: 2 };
    expect(createNewVault({ name: "x", now: NOW, kdf: owaspMinimum }).settings.kdf).toBe(owaspMinimum);
  });

  // Review kdbx-2 (Entscheidung 2026-10-17: ablehnen, nie still verändern). Der Name landet in
  // <DatabaseName> und als Name der Wurzelgruppe; der Writer entfernt solche Zeichen. Sonst wiche
  // die Datenbank im Speicher von der Datei ab, und jeder Abgleich schriebe erneut (mit Sicherung).
  it("lehnt einen Namen mit Zeichen ab, die KDBX nicht speichern kann", () => {
    for (const name of ["Tresor\u000Bneu", "a\u0000", "￾", "x\uD800"]) {
      expect(() => createNewVault({ name, now: NOW, kdf: TEST_KDF, allowWeakKdf: true }), JSON.stringify(name)).toThrow(RangeError);
    }
    expect(createNewVault({ name: "Tab\tZeile\nEmoji 🔑", now: NOW, kdf: TEST_KDF, allowWeakKdf: true }).meta.databaseName).toBe("Tab\tZeile\nEmoji 🔑");
  });
});

describe("readKdbx / writeKdbx", () => {
  it("Rundreise: was geschrieben wurde, wird genauso wieder gelesen", async () => {
    const vault = sampleVault();
    const file = await writeKdbx(vault, CREDENTIALS);
    const read = await readKdbx(file, CREDENTIALS);

    expect(comparable(read)).toEqual(comparable(vault));
    expect(read.root.groups[0]!.entries[0]!.strings.get("PIN")).toEqual({ value: "1234", protected: true });
    expect(read.root.groups[0]!.entries[0]!.attachments[0]!.data).toEqual(Uint8Array.from([0, 1, 2, 255, 254]));
    expect(read.settings).toMatchObject({ versionMinor: 0, cipher: "aes256", compression: true });
    expect({ ...read.settings.kdf, salt: undefined }).toEqual({ ...TEST_KDF, salt: undefined });
  });

  it("neue Datenbank ohne Inhalt: Rundreise ohne Unterschied (Zeiten sind schon ganze Sekunden)", async () => {
    const vault = createNewVault({ name: "Leer", now: NOW, kdf: TEST_KDF, allowWeakKdf: true });
    expect(content(await readKdbx(await writeKdbx(vault, CREDENTIALS), CREDENTIALS))).toEqual(content(vault));
  });

  it("jedes Speichern verschlüsselt neu (anderer Master-Seed/Salt), der Inhalt bleibt", async () => {
    const vault = sampleVault();
    const first = await writeKdbx(vault, CREDENTIALS);
    const second = await writeKdbx(vault, CREDENTIALS);
    expect(Buffer.from(first).equals(Buffer.from(second))).toBe(false);
    expect(comparable(await readKdbx(second, CREDENTIALS))).toEqual(comparable(await readKdbx(first, CREDENTIALS)));
  });

  it("hebt auf KDBX 4.1 an, wenn ein 4.1-Merkmal benutzt wird – ohne das Modell zu verändern", async () => {
    const vault = sampleVault();
    vault.root.tags = ["kdbx41"];
    const read = await readKdbx(await writeKdbx(vault, CREDENTIALS), CREDENTIALS);
    expect(read.settings.versionMinor).toBe(1);
    expect(read.root.tags).toEqual(["kdbx41"]);
    expect(vault.settings.versionMinor).toBe(0);
  });

  it("falsches Passwort -> KdbxError InvalidCredentials", async () => {
    const file = await writeKdbx(sampleVault(), CREDENTIALS);
    await expect(readKdbx(file, { password: "falsch" })).rejects.toMatchObject({ name: "KdbxError", code: "InvalidCredentials" });
  });

  it("createKdbxCodec benutzt dieselbe Implementierung (decode(encode(v)) = v)", async () => {
    const codec = createKdbxCodec(CREDENTIALS);
    const vault = sampleVault();
    expect(comparable(await codec.decode(await codec.encode(vault)))).toEqual(comparable(vault));
    expect(comparable(await readKdbx(await codec.encode(vault), CREDENTIALS))).toEqual(comparable(vault));
  });
});
