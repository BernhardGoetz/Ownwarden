/**
 * VaultCodec für echte KDBX4-Dateien: Datei-Bytes <-> Modell, mit den Zugangsdaten der
 * Datenbank. Die eigentliche Arbeit machen readKdbx/writeKdbx (kdbx/index.ts) – es gibt
 * genau EINE Implementierung von „Datei lesen/schreiben“, die Sync, Kommandozeile und später
 * die Erweiterung gemeinsam benutzen.
 *
 *   decode: readKdbx  (Container entschlüsseln -> XML einlesen)
 *   encode: writeKdbx (neuer innerer ChaCha20-Strom -> XML -> Container mit neuem Master-Seed,
 *           IV und KDF-Salt; bei Bedarf KDBX 4.1)
 *
 * Die Zugangsdaten bleiben in diesem Objekt; sie werden nirgends ausgegeben.
 */
import type { VaultCodec } from "../contracts";
import type { Credentials } from "../model";
import { readKdbx, writeKdbx } from "../kdbx/index";

export function createKdbxCodec(credentials: Credentials): VaultCodec {
  return {
    decode: (file) => readKdbx(file, credentials),
    encode: (vault) => writeKdbx(vault, credentials),
  };
}
