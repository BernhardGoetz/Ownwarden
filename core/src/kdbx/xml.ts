/**
 * KDBX-XML <-> Modell: die XML-Datenbank im Inneren einer KDBX-4-Datei.
 *
 * Aufbau der XML (gekürzt):
 *   <KeePassFile>
 *     <Meta> Generator, DatabaseName, CustomIcons, CustomData, … </Meta>
 *     <Root>
 *       <Group> UUID, Name, Times, CustomData, <Entry>…</Entry>*, <Group>…</Group>* </Group>
 *       <DeletedObjects> <DeletedObject> UUID, DeletionTime </DeletedObject>* </DeletedObjects>
 *     </Root>
 *   </KeePassFile>
 *
 * Ablauf beim Lesen (parseVaultXml):
 *   1. UTF-8 prüfen und XML sicher einlesen (keine DTD/Entities)          xml-dom.ts
 *   2. ALLE geschützten Werte in Dokumentreihenfolge entschlüsseln        xml-protected.ts
 *   3. Baum ins Modell übertragen, Anhänge über den Binär-Pool auflösen   xml-read.ts
 *
 * Ablauf beim Schreiben (serializeVaultXml):
 *   1. Baum aus dem Modell bauen (Klartext, Protected="True"), Pool neu   xml-write.ts
 *   2. ALLE geschützten Werte im fertigen Baum in Dokumentreihenfolge
 *      verschlüsseln                                                      xml-protected.ts
 *   3. Im Stil von KeePassXC als UTF-8 ausgeben                           xml-dom.ts
 *
 * Wichtig für Aufrufer: `stream` ist zustandsbehaftet. Für jedes Lesen und jedes Schreiben
 * einen FRISCHEN Strom erzeugen (createInnerStream); beim Speichern außerdem einen neuen
 * Schlüssel (newInnerStreamKey), siehe container.ts.
 */
import { KdbxError, type ParseVaultXml, type SerializeVaultXml } from "../contracts";
import type { Entry, Group, Vault } from "../model";
import { utf8Encode } from "./bytes";
import { MAX_XML_BYTES } from "./constants";
import { KDBX_XML_LIMITS, findXmlLimitViolation, parseXml, serializeDocument } from "./xml-dom";
import { decryptProtectedValues, encryptProtectedValues } from "./xml-protected";
import { readVault } from "./xml-read";
import { decodeUtf8Strict } from "./xml-values";
import { BinaryPoolBuilder, buildVaultDocument } from "./xml-write";

/** XML -> Modell (Vertrag ParseVaultXml in contracts.ts). */
export const parseVaultXml: ParseVaultXml = (xml, binaries, stream, settings) => {
  // Vor dem Dekodieren: Als Text und erst recht als DOM von xmldom braucht die XML ein
  // Vielfaches ihrer Größe an Speicher (Sicherheitsaudit dos-4). TooLarge statt Corrupt: Die
  // Datei ist gültig, nur zu groß für Ownwarden.
  if (xml.length > MAX_XML_BYTES) {
    throw new KdbxError("TooLarge", `XML-Datenbank: zu groß für Ownwarden – die XML hat mehr als ${MAX_XML_BYTES / (1024 * 1024)} MiB.`);
  }
  const document = parseXml(decodeUtf8Strict(xml, "XML-Datenbank"), "XML-Datenbank");
  const plaintexts = decryptProtectedValues(document, stream);
  return readVault(document, settings, { plaintexts, binaries });
};

/** Modell -> XML (Vertrag SerializeVaultXml in contracts.ts). Verändert `vault` nicht. */
export const serializeVaultXml: SerializeVaultXml = (vault, stream) => {
  const pool = new BinaryPoolBuilder();
  const document = buildVaultDocument(vault, pool);
  encryptProtectedValues(document, stream);
  const text = serializeDocument(document);
  // Was das Lesen ablehnen würde (zu tief, zu viele Bestandteile), gar nicht erst schreiben
  // (Grundregel in xml-write.ts). Die Größe in Byte prüft container.ts mit eigener Meldung.
  const problem = findXmlLimitViolation(text, { ...KDBX_XML_LIMITS, maxLength: Infinity });
  if (problem !== undefined) throw new RangeError(`Modell: Die Datenbank ließe sich so nicht wieder einlesen (${problem}).`);
  return { xml: utf8Encode(text), binaries: pool.binaries() };
};

/**
 * Kleinste KDBX-4-Nebenversion, in der sich die Datenbank ohne Verlust speichern lässt
 * (gleiche Regeln wie KeePassXC: KeePass2Writer::kdbxVersionRequired).
 *
 * serializeVaultXml schreibt 4.1-Elemente nur bei `settings.versionMinor === 1`. Wer eine
 * 4.0-Datei speichert, sollte daher vorher prüfen:
 *   settings.versionMinor = Math.max(settings.versionMinor, kdbxMinorVersionRequired(vault))
 * Nicht berücksichtigt (wie bei KeePassXC): LastModificationTime in CustomData – das ist
 * ohnehin unzuverlässig (siehe model.ts) und fällt in 4.0 einfach weg.
 */
export function kdbxMinorVersionRequired(vault: Vault): 0 | 1 {
  const iconNeeds41 = vault.meta.customIcons.some((icon) => icon.name !== undefined || icon.lastModified !== undefined);
  return iconNeeds41 || groupNeeds41(vault.root) ? 1 : 0;
}

function groupNeeds41(group: Group): boolean {
  if (group.tags.length > 0 || group.previousParentGroup !== undefined) return true;
  return group.entries.some(entryNeeds41) || group.groups.some(groupNeeds41);
}

function entryNeeds41(entry: Entry): boolean {
  if (entry.qualityCheck === false || entry.previousParentGroup !== undefined) return true;
  return entry.history.some(entryNeeds41);
}
