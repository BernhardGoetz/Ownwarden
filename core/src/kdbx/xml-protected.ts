/**
 * Geschützte Werte in der XML-Datenbank (<Value Protected="True">…</Value>).
 *
 * KDBX verschlüsselt Passwörter usw. INNERHALB der XML zusätzlich mit dem inneren
 * Zufallsstrom (siehe inner-stream.ts). In der Datei steht dann Base64 des Chiffretexts.
 *
 * Der Knackpunkt: Es gibt nur EINEN fortlaufenden Schlüsselstrom für die ganze Datei. Der
 * erste geschützte Wert im Dokument verbraucht die ersten Bytes des Stroms, der zweite die
 * nächsten usw. Wer einen geschützten Wert überspringt oder in anderer Reihenfolge
 * bearbeitet, entschlüsselt alle folgenden falsch. Deshalb:
 *
 *   Lesen:     ZUERST das ganze Dokument in Dokumentreihenfolge durchgehen und JEDEN
 *              geschützten Wert entschlüsseln – auch in Verlaufseinträgen und in Elementen,
 *              die Ownwarden gar nicht kennt. Erst danach wird das Modell gebaut.
 *   Schreiben: ZUERST den kompletten Baum mit Klartext bauen (geschützte Werte tragen
 *              Protected="True"), DANACH den fertigen Baum in Dokumentreihenfolge
 *              durchgehen und verschlüsseln. Unbekannte Elemente aus dem Modell sind dann
 *              schon an ihrem Platz und werden automatisch mit verschlüsselt.
 *
 * Wie KeePass und KeePassXC verbraucht ein LEERER geschützter Wert keine Bytes des Stroms.
 *
 * Hinweis: KeePass entschlüsselt auch geschützte Werte in unbekannten Elementen (bleibt im
 * Takt), KeePassXC überspringt unbekannte Elemente samt Inhalt. Enthält eine Datei (z. B.
 * von einem KeePass-Plugin) geschützte Werte in Elementen, die KeePassXC nicht kennt, liest
 * KeePassXC schon die Originaldatei falsch – Ownwarden macht es dadurch nicht schlimmer.
 */
import type { InnerStreamCipher } from "../contracts";
import { utf8Encode, wipe } from "./bytes";
import { childElements, plainText, type XmlElement } from "./xml-dom";
import { decodeBase64, encodeBase64, isTrueAttribute } from "./xml-values";

/** Ein einzelnes (ungepaartes) UTF-16-Surrogat. */
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

/** true, wenn das Element einen mit dem inneren Strom verschlüsselten Wert enthält. */
export function isProtectedElement(element: XmlElement): boolean {
  return isTrueAttribute(element.attributes.get("Protected"));
}

/**
 * Entschlüsselt alle geschützten Werte in Dokumentreihenfolge.
 *
 * Der Baum selbst bleibt unverändert; das Ergebnis ordnet jedem geschützten Element seinen
 * Klartext (als Bytes) zu. Bytes statt Text, weil ein geschützter Anhang (<Binary><Value
 * Protected="True">, nur in sehr alten Dateien) kein UTF-8 ist.
 */
export function decryptProtectedValues(root: XmlElement, stream: InnerStreamCipher): Map<XmlElement, Uint8Array> {
  const plaintexts = new Map<XmlElement, Uint8Array>();
  forEachInDocumentOrder(root, (element) => {
    if (!isProtectedElement(element)) return true;
    const context = `Geschützter Wert in <${element.name}>`;
    const ciphertext = decodeBase64(plainText(element, context), context);
    plaintexts.set(element, ciphertext.length === 0 ? ciphertext : stream.process(ciphertext));
    return false; // Ein geschützter Wert enthält nur Text; nicht weiter hineinsteigen.
  });
  return plaintexts;
}

/**
 * Verschlüsselt alle geschützten Werte des (fertig gebauten) Baums in Dokumentreihenfolge.
 * Vorher steht in ihnen Klartext, danach Base64 des Chiffretexts. Verändert den Baum.
 */
export function encryptProtectedValues(root: XmlElement, stream: InnerStreamCipher): void {
  forEachInDocumentOrder(root, (element) => {
    if (!isProtectedElement(element)) return true;
    const what = `Geschützter Wert in <${element.name}>`;
    const text = plainText(element, what);
    // UTF-8 kennt keine einzelnen Surrogate; TextEncoder machte still U+FFFD daraus. Ein
    // Modellfehler (vault-ops lehnt das schon ab), also RangeError (Sicherheitsaudit xml-2).
    if (LONE_SURROGATE.test(text)) throw new RangeError(`${what}: enthält ein einzelnes UTF-16-Surrogat, das UTF-8 nicht speichern kann.`);
    const plaintext = utf8Encode(text);
    element.children = plaintext.length === 0 ? [] : [encodeBase64(stream.process(plaintext))];
    wipe(plaintext);
    // KeePass erkennt nur genau "True" (KeePassXC auch "true" oder "1").
    element.attributes.set("Protected", "True");
    return false;
  });
}

/**
 * Besucht alle Elemente in Dokumentreihenfolge (Vorordnung: erst das Element, dann seine
 * Kinder von links nach rechts). Gibt `visit` false zurück, werden die Kinder dieses
 * Elements übersprungen. Ohne Rekursion, damit tiefe Bäume den Aufrufstapel nicht sprengen.
 */
function forEachInDocumentOrder(root: XmlElement, visit: (element: XmlElement) => boolean): void {
  const stack: XmlElement[] = [root];
  while (stack.length > 0) {
    const element = stack.pop()!;
    if (!visit(element)) continue;
    const children = childElements(element);
    for (let i = children.length - 1; i >= 0; i--) stack.push(children[i]!);
  }
}
