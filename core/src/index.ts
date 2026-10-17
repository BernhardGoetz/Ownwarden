/**
 * Öffentliche Schnittstelle des Ownwarden-Kerns. Wer den Kern benutzt (Browser-Erweiterung,
 * Kommandozeile, Tests), importiert von hier – nicht aus den einzelnen Dateien. So bleibt
 * klar, was „nach außen“ gehört und was internes Detail ist.
 *
 * Typischer Ablauf eines Clients:
 *
 *   const codec = createKdbxCodec({ password });
 *   let vault = await readKdbx(lokaleBytes, { password });     // oder createNewVault(...)
 *   const clock = createVaultClock(vault);
 *   setField(vault, eintragUuid, "Password", "neu", {}, clock); // nur über vault-ops ändern!
 *   const result = await syncVault(vault, new WebDavAdapter({ fileUrl, username, password: geraetepasswort }), codec, {
 *     now: () => Date.now(), merge: mergeVaults, ...DEFAULT_SYNC_SETTINGS,
 *   });
 *   vault = result.vault;                                     // neue lokale Fassung
 *   lokaleBytes = await writeKdbx(vault, { password });
 *
 * Alles hier läuft auch im Service Worker einer Browser-Erweiterung (keine Node-APIs).
 * Die Kommandozeile (cli/) gehört NICHT dazu.
 */

// Datenmodell und Verträge (Typen, Fehlerklassen, Konstanten)
export * from "./model";
export * from "./contracts";

// KDBX-Datei lesen/schreiben, neue Datenbank
export {
  createNewVault,
  DEFAULT_ROOT_GROUP_NAME,
  defaultKdbxSettings,
  kdbxMinorVersionRequired,
  readKdbx,
  writeKdbx,
  type NewVaultOptions,
} from "./kdbx/index";

// Feld-Merge, Feld-Zeitstempel, Uhr
export { mergeVaults, RECOVERY_GROUP_NAME, RECOVERY_GROUP_UUID } from "./merge/merge";
export { effectiveFieldTimes, readFieldTimes, type EffectiveFieldTimes, type FieldTime } from "./merge/field-times";
export { createVaultClock, latestVaultTime, VaultClock, type MonotonicClock } from "./merge/clock";

// Bearbeiten (der einzige Weg, Einträge und Gruppen zu ändern)
export {
  createEntry,
  createGroup,
  deleteEntry,
  deleteGroup,
  editEntry,
  findEntry,
  findEntryLocation,
  findGroup,
  findGroupLocation,
  moveEntry,
  moveGroup,
  PASSKEY_TAG,
  recycleEntry,
  removeAttachment,
  removeField,
  removePasskey,
  renameGroup,
  sanitizeTags,
  setAttachment,
  setField,
  setPasskey,
  setTags,
  type CreateEntryOptions,
  type CreateGroupOptions,
  type FieldInput,
  type SetAttachmentOptions,
  type SetFieldOptions,
} from "./merge/vault-ops";
export type { EntryLocation, GroupLocation } from "./merge/tree";

// Abgleich mit dem Speicher
export { adoptServerSettings, DEFAULT_SYNC_SETTINGS, syncVault } from "./sync/sync";
export { restampFutureTimes, type RestampResult } from "./sync/future-times";
export { createKdbxCodec } from "./sync/kdbx-codec";
export {
  BACKUP_FOLDER_NAME,
  DEFAULT_WEBDAV_TIMEOUT_MS,
  MIN_UPLOAD_BYTES_PER_SECOND,
  WebDavAdapter,
  type WebDavAdapterOptions,
} from "./sync/webdav";
export { InMemoryAdapter, InMemoryStorage, type InMemoryAdapterOptions, type InMemoryStorageOptions } from "./sync/memory-adapter";
export { vaultsEquivalent } from "./sync/vault-equal";
