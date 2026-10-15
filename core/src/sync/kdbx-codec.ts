/**
 * VaultCodec für echte KDBX4-Dateien: Datei-Bytes <-> Modell, mit den Zugangsdaten der
 * Datenbank. Verbindet die Bausteine aus kdbx/ (Rezept aus der Etappe „xml“):
 *
 *   decode: Container entschlüsseln -> XML einlesen (geschützte Werte mit dem inneren Strom
 *           der Datei entschlüsseln).
 *   encode: neuen Schlüssel für den inneren Strom (ChaCha20) erzeugen -> XML schreiben ->
 *           Container verschlüsseln (neuer Master-Seed, IV, KDF-Salt bei jedem Speichern).
 *           Braucht die Datenbank KDBX-4.1-Merkmale, wird die Version auf 4.1 angehoben.
 *
 * Die Zugangsdaten bleiben in diesem Objekt; sie werden nirgends ausgegeben.
 */
import type { VaultCodec } from "../contracts";
import type { Credentials } from "../model";
import { decryptContainer, encryptContainer } from "../kdbx/container";
import { createInnerStream, newInnerStreamKey } from "../kdbx/inner-stream";
import { kdbxMinorVersionRequired, parseVaultXml, serializeVaultXml } from "../kdbx/xml";

export function createKdbxCodec(credentials: Credentials): VaultCodec {
  return {
    async decode(file) {
      const payload = await decryptContainer(file, credentials);
      const stream = createInnerStream(payload.innerStreamId, payload.innerStreamKey);
      return parseVaultXml(payload.xml, payload.binaries, stream, payload.settings);
    },
    async encode(vault) {
      const innerStreamKey = newInnerStreamKey();
      const versionMinor = Math.max(vault.settings.versionMinor, kdbxMinorVersionRequired(vault)) as 0 | 1;
      const settings = { ...vault.settings, versionMinor };
      const { xml, binaries } = serializeVaultXml({ ...vault, settings }, createInnerStream("chacha20", innerStreamKey));
      return encryptContainer({ settings, innerStreamId: "chacha20", innerStreamKey, binaries, xml }, credentials);
    },
  };
}
