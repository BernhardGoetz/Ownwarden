/**
 * Doppelte UUIDs in EINER Datei: beim Lesen deterministisch reparieren (Review kdbx-1).
 *
 * Der ganze Kern arbeitet über UUIDs (Zusammenführen, Verschieben, Lösch-Vermerke). Haben
 * zwei Gruppen oder Einträge einer Datei dieselbe UUID (in der KeePass-Welt kommt das vor,
 * KeePass 2.x bietet dafür eigens „doppelte UUIDs reparieren“ an), würde der Abgleich sie
 * still zu EINEM Objekt zusammenlegen – mit vollem Verlauf wäre die unterlegene Fassung samt
 * Passwort ganz verschwunden. Deshalb bekommt beim Lesen jedes SPÄTERE Vorkommen eine neue
 * UUID. Sie wird aus der alten ABGELEITET, nicht gewürfelt: Jedes Gerät, das dieselbe Datei
 * liest, kommt auf dieselbe neue UUID und sieht beim Abgleich dasselbe Objekt. Beim nächsten
 * Speichern steht die neue UUID in der Datei; danach ist sie repariert.
 *
 * Verfahren (verbindlich, auch für die Kotlin-Fassung; siehe spec/README.md):
 *   1. Vergeben = alle UUIDs der Datei: jede <UUID> einer Gruppe, eines Eintrags, eines
 *      Verlaufseintrags und jedes <DeletedObject>, dazu die Null-UUID.
 *   2. Gruppen und Einträge (OHNE Verlaufseinträge) werden in Dokumentreihenfolge
 *      durchlaufen (Reihenfolge der öffnenden Tags <Group>/<Entry>; eine Gruppe kommt also
 *      vor ihrem Inhalt). Gruppen und Einträge teilen sich EINEN Namensraum (wie bei
 *      KeePass; auch Lösch-Vermerke unterscheiden nicht zwischen Gruppe und Eintrag).
 *   3. Das erste Vorkommen einer UUID behält sie. Für jedes weitere Vorkommen der UUID u:
 *      k = Zähler je u (beginnt bei 0). Wiederhole k := k + 1,
 *        Kandidat = erste 16 Byte von SHA-256( UTF-8("Ownwarden-Duplicate")
 *                                              || 16 Byte von u || k als uint32 Little Endian ),
 *      solange der Kandidat schon vergeben ist. Der Kandidat wird die neue UUID und gilt ab
 *      dann als vergeben; der Zähler von u bleibt für das nächste Vorkommen stehen.
 *   4. Die Verlaufseinträge eines umbenannten Eintrags bekommen dieselbe neue UUID (sie
 *      gehören zu ihm; wie KeePass PwEntry.SetUuid(…, true)). Verlaufseinträge zählen selbst
 *      NIE als Duplikat – sie tragen rechtmäßig die UUID ihres Eintrags.
 *   Verweise auf die alte UUID (RecycleBinUUID, PreviousParentGroup, {REF:…}) werden nicht
 *   umgeschrieben; sie meinen weiterhin das erste Vorkommen.
 */
import { sha256 } from "@noble/hashes/sha2.js";
import { NULL_UUID, type Entry, type Group, type Uuid } from "../model";
import { concatBytes, u32le, utf8Encode } from "./bytes";
import { decodeBase64, encodeBase64 } from "./xml-values";

const DUPLICATE_UUID_PREFIX = utf8Encode("Ownwarden-Duplicate");

/** Eine Gruppe oder ein (aktueller) Eintrag; die Liste dafür steht in Dokumentreihenfolge. */
export type UuidOwner = { kind: "group"; group: Group } | { kind: "entry"; entry: Entry };

/** Kandidat Nummer `index` (ab 1) für ein weiteres Vorkommen von `original` (Schritt 3). */
export function deriveDuplicateUuid(original: Uuid, index: number): Uuid {
  const input = concatBytes(DUPLICATE_UUID_PREFIX, decodeBase64(original, "UUID"), u32le(index));
  return encodeBase64(sha256(input).subarray(0, 16));
}

/**
 * Gibt jedem späteren Vorkommen einer UUID eine neue (Schritte 1–4 oben). Verändert die
 * Objekte in `owners` direkt.
 *
 * @param owners     alle Gruppen und Einträge der Datei in Dokumentreihenfolge
 * @param otherUuids alle übrigen UUIDs der Datei (Verlaufseinträge, DeletedObjects)
 */
export function repairDuplicateUuids(owners: readonly UuidOwner[], otherUuids: Iterable<Uuid>): void {
  const taken = new Set<Uuid>([NULL_UUID, ...otherUuids]);
  for (const owner of owners) taken.add(uuidOf(owner));

  const seen = new Set<Uuid>();
  const lastIndex = new Map<Uuid, number>();
  for (const owner of owners) {
    const original = uuidOf(owner);
    if (!seen.has(original)) {
      seen.add(original);
      continue;
    }
    let index = lastIndex.get(original) ?? 0;
    let candidate: Uuid;
    do {
      index++;
      candidate = deriveDuplicateUuid(original, index);
    } while (taken.has(candidate));
    lastIndex.set(original, index);
    taken.add(candidate);

    if (owner.kind === "group") {
      owner.group.uuid = candidate;
    } else {
      owner.entry.uuid = candidate;
      for (const item of owner.entry.history) item.uuid = candidate;
    }
  }
}

function uuidOf(owner: UuidOwner): Uuid {
  return owner.kind === "group" ? owner.group.uuid : owner.entry.uuid;
}
