/**
 * Wurde eine Datei der Kommandozeile direkt gestartet (und nicht z. B. aus einem Test
 * importiert)? Nur Node, nur für die Kommandozeile.
 *
 * Node löst das gestartete Skript zu seinem echten Pfad auf (Symlinks, unter Windows auch
 * Junctions); import.meta.url ist also der echte Pfad. process.argv[1] bleibt dagegen so, wie es
 * angegeben wurde. Ein Vergleich ohne realpath hielte einen Start über einen Symlink für
 * „importiert“: Das Programm täte nichts und endete mit Exit-Code 0 – beim Servertest hieße das
 * „sicher“ (Review xc-5). Deshalb werden beide Seiten mit realpath aufgelöst; unter Windows
 * zählt die Groß-/Kleinschreibung nicht (dort ist z. B. „c:\“ dasselbe wie „C:\“).
 */
import { realpathSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

/** true, wenn `script` (Standard: process.argv[1]) dieselbe Datei ist wie das Modul `moduleUrl`. */
export function isMainModule(moduleUrl: string, script: string | undefined = process.argv[1], platform: NodeJS.Platform = process.platform): boolean {
  if (script === undefined) return false;
  let started: string;
  let module: string;
  try {
    started = realpathSync(resolve(script));
    module = realpathSync(fileURLToPath(moduleUrl));
  } catch {
    return false; // z. B. argv[1] ist gar keine Datei (REPL, node -e)
  }
  return platform === "win32" ? started.toLowerCase() === module.toLowerCase() : started === module;
}
