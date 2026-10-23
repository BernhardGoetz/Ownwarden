/**
 * Die öffentliche Schnittstelle (index.ts) reicht für einen kompletten Client-Ablauf:
 * neue Datenbank, Eintrag anlegen, auf einen Speicher hochladen, auf einem zweiten „Gerät“
 * ändern, abgleichen – nur mit Importen aus index.ts.
 */
import { describe, expect, it } from "vitest";
import * as api from "./index";

const TEST_KDF: api.KdfParams = { type: "argon2id", salt: new Uint8Array(32), parallelism: 1, memoryBytes: 1 << 20, iterations: 2, version: 0x13 };

describe("öffentliche Schnittstelle", () => {
  it("enthält die Bausteine aus allen Teilen des Kerns", () => {
    for (const name of [
      "readKdbx",
      "writeKdbx",
      "createNewVault",
      "createKdbxCodec",
      "mergeVaults",
      "syncVault",
      "createVaultClock",
      "createEntry",
      "setField",
      "setPasskey",
      "recycleEntry",
      "effectiveFieldTimes",
    ] as const) {
      expect(typeof api[name], name).toBe("function");
    }
    expect(typeof api.WebDavAdapter).toBe("function");
    expect(typeof api.InMemoryAdapter).toBe("function");
    expect(new api.KdbxError("Corrupt", "x")).toBeInstanceOf(Error);
    expect(api.FIELD_TIMES_KEY).toBe("Ownwarden.FieldTimes");
    expect(api.DEFAULT_SYNC_SETTINGS).toEqual({ maxAttempts: 5, maxClockSkewMs: 120_000, backupsToKeep: 20 });
  });

  it("ein kompletter Ablauf mit zwei Geräten nur über index.ts", async () => {
    const credentials = { password: "Api-Test" };
    const codec = api.createKdbxCodec(credentials);
    const storage = new api.InMemoryStorage();
    const options = { now: () => Date.now(), merge: api.mergeVaults, ...api.DEFAULT_SYNC_SETTINGS };

    const vault = api.createNewVault({ name: "Api", now: Date.now(), kdf: TEST_KDF, allowWeakKdf: true });
    const entry = api.createEntry(vault, vault.root.uuid, { Title: "Mail", UserName: "alice", Password: "alt" }, api.createVaultClock(vault));
    const created = await api.syncVault(vault, new api.InMemoryAdapter({ storage, name: "Vivaldi" }), codec, options);
    expect(created.created).toBe(true);

    const chromeVault = await api.readKdbx(storage.current()!.data, credentials);
    api.setField(chromeVault, entry.uuid, "Password", "neu", {}, api.createVaultClock(chromeVault));
    await api.syncVault(chromeVault, new api.InMemoryAdapter({ storage, name: "Chrome" }), codec, options);

    const result = await api.syncVault(created.vault, new api.InMemoryAdapter({ storage, name: "Vivaldi" }), codec, options);
    expect(api.findEntry(result.vault, entry.uuid)?.strings.get("Password")?.value).toBe("neu");
    expect(result.written).toBe(false);
  });
});
