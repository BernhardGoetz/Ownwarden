/**
 * Review kdbx-2 (Regressionstest): Werte, die der Writer still verändert.
 *
 * escapeText/escapeAttribute (xml-dom.ts) entfernen in XML ungültige Zeichen (z. B. U+000B,
 * den „manuellen Zeilenumbruch“ aus Word) aus ungeschützten Werten; geschützte Werte gehen
 * über TextEncoder, der ungepaarte Surrogate durch U+FFFD ersetzt. vault-ops nimmt diese
 * Zeichen aber an. syncVault gibt das Modell im Speicher zurück (mit den Zeichen), die Datei
 * hat sie nicht – Modell und Datei werden nie gleich. Ein Client, der wie in src/index.ts
 * beschrieben mit result.vault weiterarbeitet, schreibt deshalb bei JEDEM Abgleich neu und
 * legt jedes Mal eine Sicherungskopie an (nach 20 Abgleichen sind alle echten älteren
 * Sicherungen verdrängt).
 *
 * Erwartet: Nach dem Anlegen schreibt höchstens noch EIN Abgleich (Angleichen an die Datei),
 * danach keiner mehr. Lehnt vault-ops oder der Writer solche Werte klar ab (ohne zu
 * schreiben), ist das ebenfalls in Ordnung.
 */
import { describe, expect, it } from "vitest";
import { createVaultClock } from "../../src/merge/clock";
import { mergeVaults } from "../../src/merge/merge";
import { createEntry } from "../../src/merge/vault-ops";
import type { Vault } from "../../src/model";
import { createKdbxCodec } from "../../src/sync/kdbx-codec";
import { InMemoryAdapter, InMemoryStorage } from "../../src/sync/memory-adapter";
import { syncVault } from "../../src/sync/sync";
import { newVault, secret, T0 } from "../helpers/vault-builder";

const codec = createKdbxCodec({ password: "Review-kdbx-2" });
const FOLLOW_UP_SYNCS = 5;

type Outcome = { rejected: true } | { rejected: false; writesAfterCreate: number; backups: number };

/** Legt einen Eintrag mit `fields` an, lädt ihn hoch und gleicht danach FOLLOW_UP_SYNCS-mal ab (mit result.vault weiter). */
async function createAndSyncRepeatedly(fields: Parameters<typeof createEntry>[2]): Promise<Outcome> {
  let time = T0 + 123;
  const storage = new InMemoryStorage({ serverClock: () => time });
  const adapter = new InMemoryAdapter({ storage });
  const options = () => ({ now: () => time, merge: mergeVaults, maxAttempts: 3, maxClockSkewMs: 120_000, backupsToKeep: 20 });

  let vault: Vault = newVault();
  try {
    createEntry(vault, vault.root.uuid, fields, createVaultClock(vault, () => (time += 1234)));
  } catch {
    return { rejected: true }; // vault-ops lehnt den Wert ab: in Ordnung
  }

  time += 1000;
  try {
    vault = (await syncVault(vault, adapter, codec, options())).vault;
  } catch (error) {
    // Der Writer lehnt den Wert ab: in Ordnung, wenn nichts geschrieben wurde.
    expect(error).toBeInstanceOf(Error);
    expect(storage.current()).toBeNull();
    return { rejected: true };
  }

  let writesAfterCreate = 0;
  for (let round = 0; round < FOLLOW_UP_SYNCS; round++) {
    time += 1000;
    const result = await syncVault(vault, adapter, codec, options());
    if (result.written) writesAfterCreate++;
    vault = result.vault;
  }
  return { rejected: false, writesAfterCreate, backups: storage.backups.length };
}

describe("Review kdbx-2: still veränderte Werte führen zu endlosem Hochladen", () => {
  it("Review kdbx-2: ungeschützter Titel mit U+000B wird nicht bei jedem Abgleich erneut hochgeladen", async () => {
    const outcome = await createAndSyncRepeatedly({ Title: "Zeile1\u000BZeile2" });
    if (outcome.rejected) return;
    expect(outcome.writesAfterCreate).toBeLessThanOrEqual(1);
    expect(outcome.backups).toBeLessThanOrEqual(1);
  });

  it("Review kdbx-2: geschütztes Passwort mit ungepaartem Surrogat wird nicht bei jedem Abgleich erneut hochgeladen", async () => {
    const outcome = await createAndSyncRepeatedly({ Title: "Surrogat", Password: secret("ab\uD800") });
    if (outcome.rejected) return;
    expect(outcome.writesAfterCreate).toBeLessThanOrEqual(1);
    expect(outcome.backups).toBeLessThanOrEqual(1);
  });

  it("Kontrolle: ein normaler Eintrag wird nach dem Anlegen nicht erneut hochgeladen", async () => {
    const outcome = await createAndSyncRepeatedly({ Title: "Normal", Password: secret("ab") });
    expect(outcome).toEqual({ rejected: false, writesAfterCreate: 0, backups: 0 });
  });
});
