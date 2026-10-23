/**
 * Text aus fremder Quelle für Meldungen aufbereiten (Sicherheitsaudit leak-1).
 *
 * Fremd heißt: vom Server (Header, PROPFIND-Antworten) oder aus Teilen einer Tresor-Datei, die
 * noch nicht geprüft sind (äußerer Header vor dem HMAC). Ein Angreifer bestimmt diesen Text
 * frei. Unverändert in einer Fehlermeldung könnte er das Terminal steuern (ESC-Sequenzen),
 * Zeilen vortäuschen (Zeilenumbrüche), die Leserichtung drehen (Bidi-Steuerzeichen) oder die
 * Ausgabe mit Megabytes füllen.
 *
 * displayText ersetzt deshalb alle Steuerzeichen (C0, DEL, C1), Bidi-Steuerzeichen,
 * Zeilen-/Absatztrenner und einzelne Surrogate durch eine sichtbare Schreibweise (\x1b, \u202e)
 * und kürzt auf maxLength Zeichen.
 */

const UNSAFE =
  /[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069\u2028\u2029]|[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/g;

function escapeChar(char: string): string {
  const code = char.charCodeAt(0);
  return code <= 0xff ? `\\x${code.toString(16).padStart(2, "0")}` : `\\u${code.toString(16).padStart(4, "0")}`;
}

/** Fremden Text sicher darstellbar machen; längere Texte werden mit „…“ gekürzt. */
export function displayText(raw: string, maxLength = 80): string {
  const shortened = raw.length > maxLength ? `${raw.slice(0, maxLength)}…` : raw;
  return shortened.replace(UNSAFE, escapeChar);
}
