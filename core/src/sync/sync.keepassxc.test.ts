/**
 * syncVault mit einer Datei, die zwischendurch KeePassXC 2.7.6 geöffnet, geändert und
 * gespeichert hat (z. B. am PC, direkt im Nextcloud-Ordner). KeePassXC formt dabei vieles um
 * (Tags sortiert, Anhänge geschützt, CR -> LF, Standard-AutoType, _LAST_MODIFIED …).
 *
 * Verdacht: Ownwarden hält diese Umformungen für Änderungen und schreibt nach jedem
 * Speichern in KeePassXC zurück – oder zwei Geräte schreiben sich danach gegenseitig
 * ihre Fassung zurück („Ping-Pong“). Wird übersprungen, wenn keepassxc-cli fehlt.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createTmpDir, hasKeepassxc, removeTmpDir, runKpxcOk, showKpxcEntry } from "../../test/helpers/keepassxc";
import { entryByTitle, newGroup, newVault, uuidFromName } from "../../test/helpers/vault-builder";
import type { SyncOptions } from "../contracts";
import type { Vault } from "../model";
import { createVaultClock } from "../merge/clock";
import { mergeVaults } from "../merge/merge";
import { createEntry, editEntry, setAttachment, setField, setTags } from "../merge/vault-ops";
import { createKdbxCodec } from "./kdbx-codec";
import { InMemoryAdapter, InMemoryStorage } from "./memory-adapter";
import { syncVault } from "./sync";

const PASSWORD = "Sync-KeePassXC-äöü";
const codec = createKdbxCodec({ password: PASSWORD });
const options = (): SyncOptions => ({ now: () => Date.now(), merge: mergeVaults, maxAttempts: 3, maxClockSkewMs: 120_000, backupsToKeep: 5 });
const waitForNextSecond = () => new Promise((resolve) => setTimeout(resolve, 1100));

/** Datenbank mit Merkmalen, die KeePassXC beim Speichern umformt. */
function richVault(): Vault {
  const vault = newVault({ root: newGroup({ uuid: uuidFromName("root"), name: "Root" }) });
  vault.meta.customIcons.push({ uuid: uuidFromName("icon"), data: Uint8Array.from([0x89, 0x50, 0x4e, 0x47, 1, 2, 3]) });
  const clock = createVaultClock(vault);
  const mail = createEntry(vault, vault.root.uuid, { Title: "Mail", UserName: "alice", Password: "pw-alt", Notes: "Zeile 1\r\nZeile 2" }, clock, {
    uuid: uuidFromName("mail"),
  });
  setTags(vault, mail.uuid, ["Zeta", "alpha", "Mitte"], clock);
  setAttachment(vault, mail.uuid, "b.txt", new TextEncoder().encode("B"), { protected: false }, clock);
  setAttachment(vault, mail.uuid, "a.txt", new TextEncoder().encode("A"), { protected: false }, clock);
  editEntry(vault, mail.uuid, (draft) => {
    draft.iconId = 12;
    draft.customIconUuid = uuidFromName("icon");
  }, clock);
  createEntry(vault, vault.root.uuid, { Title: "Dummy" }, clock, { uuid: uuidFromName("dummy") });
  return vault;
}

describe.skipIf(!hasKeepassxc())("syncVault nach Speichern in KeePassXC", () => {
  let dir: string;
  beforeAll(() => {
    dir = createTmpDir("sync-keepassxc");
  });
  afterAll(() => {
    if (dir) removeTmpDir(dir);
  });

  /** Lässt KeePassXC die aktuelle Server-Datei bearbeiten und legt das Ergebnis zurück auf den „Server“. */
  async function editInKeePassXC(storage: InMemoryStorage, args: string[]): Promise<void> {
    const path = join(dir, `kpxc-${Date.now()}.kdbx`);
    writeFileSync(path, storage.current()!.data);
    await waitForNextSecond(); // KeePassXC-Zeiten sind sekundengenau
    await runKpxcOk(["edit", "-q", ...args.slice(0, -1), path, args.at(-1)!], `${PASSWORD}\n`);
    storage.put(new Uint8Array(readFileSync(path)));
  }

  it("Gerät ohne eigene Änderung übernimmt die KeePassXC-Änderung, schreibt höchstens einmal, danach Ruhe", async () => {
    const storage = new InMemoryStorage();
    const vivaldi = new InMemoryAdapter({ storage, name: "Vivaldi" });
    const created = await syncVault(richVault(), vivaldi, codec, options());

    await editInKeePassXC(storage, ["-u", "geändert", "Dummy"]);
    // Ein Schreiben ist hier gewollt: Der Merge trägt für die von KeePassXC geänderten Felder
    // die Änderungszeit in Ownwarden.FieldTimes ein (PROJECT-CONTEXT, „Änderungen durch andere
    // Programme“). Die Umformungen von KeePassXC (CR -> LF, IconID, Tag-Reihenfolge …) gelten
    // dagegen nicht als Änderung; sie dürfen kein weiteres Schreiben auslösen.
    const first = await syncVault(created.vault, vivaldi, codec, options());
    const second = await syncVault(first.vault, vivaldi, codec, options());

    expect(entryByTitle(second.vault, "Dummy").strings.get("UserName")?.value).toBe("geändert");
    expect(second.written).toBe(false);
    expect(vivaldi.stats.writes).toBeLessThanOrEqual(2); // Anlegen + höchstens einmal danach
    expect(entryByTitle(await codec.decode(storage.current()!.data), "Dummy").strings.get("UserName")?.value).toBe("geändert");
  });

  it("zwei Geräte und KeePassXC ändern verschiedene Felder: alles kommt an, danach schreibt niemand mehr", async () => {
    const storage = new InMemoryStorage();
    const vivaldi = new InMemoryAdapter({ storage, name: "Vivaldi" });
    const chrome = new InMemoryAdapter({ storage, name: "Chrome" });
    const mail = uuidFromName("mail");
    let vaultA = (await syncVault(richVault(), vivaldi, codec, options())).vault;
    let vaultB = await codec.decode(storage.current()!.data);

    await editInKeePassXC(storage, ["-u", "bob", "Mail"]);
    setField(vaultA, mail, "Password", "pw-vivaldi", {}, createVaultClock(vaultA));
    setField(vaultB, mail, "URL", "https://mail.example", {}, createVaultClock(vaultB));

    for (let round = 0; round < 2; round++) {
      vaultA = (await syncVault(vaultA, vivaldi, codec, options())).vault;
      vaultB = (await syncVault(vaultB, chrome, codec, options())).vault;
    }
    const writes = vivaldi.stats.writes + chrome.stats.writes;
    vaultA = (await syncVault(vaultA, vivaldi, codec, options())).vault;
    vaultB = (await syncVault(vaultB, chrome, codec, options())).vault;
    expect(vivaldi.stats.writes + chrome.stats.writes).toBe(writes);

    for (const vault of [vaultA, vaultB, await codec.decode(storage.current()!.data)]) {
      const entry = entryByTitle(vault, "Mail");
      expect(entry.strings.get("UserName")?.value).toBe("bob");
      expect(entry.strings.get("Password")?.value).toBe("pw-vivaldi");
      expect(entry.strings.get("URL")?.value).toBe("https://mail.example");
    }
    // KeePassXC kann die Datei weiterhin öffnen und sieht alle drei Änderungen.
    const path = join(dir, "final.kdbx");
    writeFileSync(path, storage.current()!.data);
    const shown = await showKpxcEntry(path, PASSWORD, "Mail", { showProtected: true, attributes: ["UserName", "Password", "URL"] });
    expect(shown).toBe("bob\npw-vivaldi\nhttps://mail.example\n");
  });
});
