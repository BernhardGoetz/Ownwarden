# Ownwarden-Kern (Prototyp)

> ⚠️ **PROTOTYP – NUR FÜR TESTDATEN.** Keine echten Passwörter, keine echte Tresor-Datei,
> nur Test-Zugänge und Testordner in der Cloud. Bitwarden bleibt bis Version 1 in Benutzung.

Dieser Ordner enthält den TypeScript-Kern von Ownwarden: KDBX-4-Dateien lesen und schreiben,
zwei Fassungen einer Datenbank Feld für Feld zusammenführen und über WebDAV (Nextcloud,
MagentaCLOUD) abgleichen. Der Kern läuft im Browser (später im Service Worker der Erweiterung)
und unter Node. Dazu gibt es zwei kleine Kommandozeilen-Programme zum Ausprobieren.

Hintergrund und Entscheidungen: [`../PROJECT-CONTEXT.md`](../PROJECT-CONTEXT.md).
Die genauen Merge-Regeln: [`../spec/README.md`](../spec/README.md).

---

## Was der Prototyp kann

- **KDBX 4.0 und 4.1 lesen und schreiben** – die Dateien öffnet KeePassXC (geprüft mit 2.7.6).
  - Lesen: AES-256 oder ChaCha20; Schlüsselableitung Argon2d, Argon2id oder AES-KDF; innerer
    Strom ChaCha20 oder Salsa20.
  - Schreiben: Die Einstellungen der Datei bleiben (Verschlüsselung, Schlüsselableitung,
    Kompression); Master-Seed, IV und Salt sind bei jedem Speichern neu. Neue Datenbanken:
    KDBX 4.0, AES-256, Argon2id (64 MiB, 3 Durchläufe, 2 Spuren), Papierkorb eingeschaltet,
    Verlauf höchstens 10 Fassungen / 6 MiB – wie bei KeePassXC. Braucht eine Datenbank
    4.1-Merkmale (z. B. Tags an Gruppen), wird automatisch 4.1 geschrieben.
  - Gruppen, Einträge, eigene Felder (geschützt/ungeschützt), Anhänge (auch Binärdaten),
    Tags, Verlauf, Papierkorb, Lösch-Vermerke, eigene Icons, Passkeys im KeePassXC-Schema.
    Alles, was Ownwarden nicht kennt (z. B. AutoType, Farben, MemoryProtection), bleibt
    unverändert erhalten.
  - Dateien, in denen eine Gruppen- oder Eintrags-UUID mehrfach vorkommt, werden beim Lesen
    repariert: Das spätere Vorkommen bekommt eine abgeleitete neue UUID (auf jedem Gerät
    dieselbe), es geht nichts verloren; beim nächsten Speichern steht sie in der Datei
    (Regel: `../spec/README.md` 5.2).
- **Feld-Merge** („neueste Änderung gewinnt – pro Feld“) mit eigenen Feld-Zeitstempeln
  (`Ownwarden.FieldTimes` im CustomData jedes Eintrags). Änderungen aus KeePassXC werden
  erkannt – genau die geänderten Felder bekommen die Änderungszeit von KeePassXC.
  Löschen gegen Ändern, Papierkorb, verschobene Einträge, gelöschte Gruppen
  (Wiederherstellungsgruppe), Verlauf beider Seiten.
- **WebDAV-Abgleich**: nur bedingtes Schreiben (`If-Match`/`If-None-Match: *`), bei `412`
  neu lesen und zusammenführen, vor jedem Überschreiben eine Sicherungskopie (eine pro
  Fassung), Prüfung der Geräteuhr gegen den Server; Zeitstempel aus der Zukunft (Uhr ging beim
  Bearbeiten vor) werden nicht hochgeladen, sondern erst repariert.
- **Kommandozeile** `npm run proto` zum Ausprobieren (siehe unten; sichert die lokale Datei,
  bevor ein Abgleich sie ersetzt) und der **WebDAV-Servertest** `npm run webdav-probe` für
  MagentaCLOUD und Nextcloud.

## Was der Prototyp (noch) nicht kann

- Keine Browser-Erweiterung, kein Autofill, kein Android, keine Passkey-Anmeldung (Passkeys
  werden nur gespeichert und abgeglichen). Kein Bitwarden-Import.
- Kein KDBX 3.x (z. B. aus `keepassxc-cli db-create`), keine Twofish-Verschlüsselung.
- Schlüsseldateien: im Kern vorbereitet (32-Byte-Schlüssel), die Kommandozeile kann sie nicht.
- Datenbank-Einstellungen (Schlüsselableitung, Verlaufsgrenzen, Beschreibung …) ändert
  Ownwarden nicht; beim Abgleich gilt die Fassung auf dem Server.
- Kein manuelles Sortieren; der Signaturzähler von Passkeys wird noch nicht gespeichert.

---

## Welche Datei macht was?

Für die Fehlersuche: Jede Datei beginnt mit einem Kommentar, der erklärt, was sie tut und
warum. Die Pfeile zeigen die Richtung der Abhängigkeiten.

```
index.ts (öffentliche Schnittstelle)
   ├─ kdbx/   Datei  <->  Modell (model.ts)
   ├─ merge/  zwei Modelle  ->  ein Modell
   └─ sync/   Modell  <->  WebDAV-Server   (benutzt kdbx/ und merge/)
cli/  Kommandozeilen-Programme (nur Node, nicht Teil der Bibliothek)
```

| Datei | Aufgabe |
|---|---|
| `src/index.ts` | Öffentliche Schnittstelle: alles, was ein Client (Erweiterung, Kommandozeile) braucht. |
| `src/model.ts` | Das Datenmodell: `Vault`, `Group`, `Entry`, Zeiten in Millisekunden. |
| `src/contracts.ts` | Verträge zwischen den Teilen (Funktionssignaturen), Fehlerklassen, `SyncResult`. |
| **kdbx/** | |
| `src/kdbx/index.ts` | `readKdbx`, `writeKdbx`, `createNewVault` – der Einstieg für Datei-Zugriffe. |
| `src/kdbx/container.ts` | Äußere Hülle: Header prüfen, Schlüssel ableiten, ver-/entschlüsseln. |
| `src/kdbx/header.ts`, `inner-header.ts`, `hmac-block-stream.ts` | Aufbau der Datei: Header, innerer Header (Anhänge), HMAC-gesicherte Blöcke. |
| `src/kdbx/kdf.ts`, `keys.ts`, `crypto.ts` | Schlüsselableitung (Argon2 über hash-wasm, AES-KDF), Schlüssel, WebCrypto/ChaCha20. |
| `src/kdbx/inner-stream.ts` | Innerer Zufallsstrom, der Passwörter in der XML schützt. |
| `src/kdbx/xml.ts` (+ `xml-read.ts`, `xml-write.ts`, `xml-dom.ts`, `xml-protected.ts`, `xml-values.ts`) | XML <-> Modell. Lesen und Schreiben im Stil von KeePassXC. |
| `src/kdbx/duplicate-uuids.ts` | Repariert beim Lesen doppelte UUIDs von Gruppen/Einträgen (abgeleitete neue UUID, spec 5.2). |
| `src/kdbx/settings.ts`, `constants.ts`, `bytes.ts`, `compression.ts`, `variant-dictionary.ts` | Standardwerte, Konstanten, Hilfsfunktionen. |
| **merge/** | |
| `src/merge/merge.ts` | `mergeVaults`: Ablauf des Zusammenführens (Einträge, Gruppen, Löschungen, Meta). |
| `src/merge/merge-entry.ts`, `merge-group.ts`, `merge-meta.ts`, `history.ts` | Einzelne Einträge, Gruppen, Meta-Angaben, Verlauf zusammenführen. |
| `src/merge/fields.ts`, `field-times.ts`, `encoding.ts` | Was ein „Feld“ ist; `Ownwarden.FieldTimes` lesen/schreiben; Erkennung externer Änderungen. |
| `src/merge/clock.ts` | Monotone Uhr: neue Zeitstempel sind immer die neuesten. |
| `src/merge/vault-ops.ts` | **Der einzige Weg, Einträge zu ändern** (anlegen, Feld setzen, Anhang, Passkey, verschieben, löschen …). |
| **sync/** | |
| `src/sync/sync.ts` | `syncVault`: lesen → Uhr prüfen → Zeitstempel aus der Zukunft? → zusammenführen → sichern → bedingt schreiben → aufräumen; `DEFAULT_SYNC_SETTINGS`. |
| `src/sync/future-times.ts` | `restampFutureTimes`: Zeitstempel aus der Zukunft auf „jetzt“ setzen (Reparatur nach `FutureTimestampsError`). |
| `src/sync/webdav.ts` (+ `http.ts`, `multistatus.ts`, `backup-names.ts`) | `WebDavAdapter`: GET/PUT mit ETags, Sicherungskopien, Aufräumen, Zeitlimit gegen Stillstand. |
| `src/sync/kdbx-codec.ts` | Verbindet Sync und Datei (`readKdbx`/`writeKdbx` mit Master-Passwort). |
| `src/sync/vault-equal.ts` | „Inhaltlich gleich?“ – verhindert unnötiges Hochladen. |
| `src/sync/memory-adapter.ts` | Speicher im Arbeitsspeicher (Tests, Ausprobieren ohne Server). |
| **cli/** (nur Node) | |
| `src/cli/ownwarden-proto.ts` (+ `prompt.ts`, `atomic-file.ts`, `local-backups.ts`, `main-module.ts`) | Prototyp-Kommandozeile; verdeckte Abfrage, atomares Schreiben, lokale Sicherungen. |
| `src/cli/webdav-probe.ts` | WebDAV-Servertest. |
| **Tests** | |
| `src/**/*.test.ts` | Tests neben dem Code (Einheit, KeePassXC-Interop `*.interop.test.ts`, Server `*.server*.test.ts`). |
| `test/interop/` | Zusammenspiel mit KeePassXC über die öffentlichen Funktionen. |
| `test/e2e/` | Ende-zu-Ende-Abgleich: zwei Browser, KeePassXC, echter WebDAV-Testserver. |
| `test/helpers/` | Hilfen: KeePassXC aufrufen, WebDAV-Testserver starten, Test-Datenbanken bauen. |
| `../spec/merge-cases/` | Sprachunabhängige Merge-Testfälle (müssen auch für Kotlin gelten). |
| `../tools/webdav-test-server/` | SabreDAV-Testserver (verhält sich beim Schreiben wie Nextcloud). |

**Wo anfangen bei einem Fehler?**
- Datei lässt sich nicht öffnen / KeePassXC meckert → `kdbx/container.ts`, dann `kdbx/xml-read.ts` bzw. `xml-write.ts`.
- Ein Feld wurde falsch zusammengeführt → zuerst einen Testfall in `../spec/merge-cases/` anlegen
  (Vorlage: ein vorhandener), dann `merge/field-times.ts` und `merge/merge-entry.ts`.
- Abgleich schreibt zu oft oder gar nicht → `sync/sync.ts` und `sync/vault-equal.ts`.
- Server-Fehler (401, 409, 412, 423 …) → `sync/webdav.ts`; den WebDAV-Servertest laufen lassen.

---

## Tests laufen lassen

Voraussetzungen: Node ≥ 22.12 (das verlangen vite und rolldown, auf denen vitest aufbaut).
Für einen Teil der Tests außerdem **KeePassXC 2.7** (Programm `keepassxc-cli`) sowie
**PHP ≥ 8.1 mit Composer** (WebDAV-Testserver). Fehlt eines davon, werden die betroffenen
Tests übersprungen (nicht als Fehler gezählt) – `npm test` endet dann trotzdem mit Exit-Code 0,
obwohl kein Interop-Test lief. **Strenger Modus:** Mit `OWNWARDEN_REQUIRE_TOOLS=1` ist ein
fehlendes `keepassxc-cli` oder PHP ein Fehler. So muss jeder Lauf aussehen, der als Nachweis
gilt (z. B. vor dem Umzug, siehe PROJECT-CONTEXT, oder in CI).

```bash
cd core
npm install                 # einmalig
npm test                    # alle Tests (ca. 1 min)
OWNWARDEN_REQUIRE_TOOLS=1 npm test   # dasselbe, aber fehlende Werkzeuge sind ein Fehler
npx vitest run test/e2e     # nur einen Ordner oder eine Datei
npm run typecheck           # TypeScript-Prüfung (tsc --noEmit)
```

`npm install` braucht keine besonderen Einstellungen (das frühere `legacy-peer-deps=true` in
`core/.npmrc` war unnötig und ist entfernt: Alle Peer-Abhängigkeiten passen, geprüft mit einer
frischen Installation am 2026-10-17).

Temporäre Dateien der Tests landen in `core/test/.tmp/` (von git ignoriert) und werden
danach gelöscht. Die Tests benutzen nur erfundene Testpasswörter.

---

## Die Kommandozeile ausprobieren

`npm run proto -- --help` zeigt alle Befehle. Die lokale `.kdbx`-Datei ist der
Zwischenspeicher eines „Clients“ – so wie später die Kopie in Vivaldi, Chrome oder auf dem
Handy. Passwörter nie auf der Kommandozeile angeben: Sie werden verdeckt abgefragt oder aus
Umgebungsvariablen gelesen (`OWNWARDEN_MASTER_PASSWORD`, `OWNWARDEN_WEBDAV_PASSWORD`,
`OWNWARDEN_ENTRY_PASSWORD`, `OWNWARDEN_FIELD_VALUE`). Umgebungsvariablen sind bequem, aber
für andere Programme desselben Benutzers sichtbar – auch deshalb nur für Testdaten.

```bash
cd core
npm run proto -- init test.kdbx                      # fragt zweimal nach dem Master-Passwort
npm run proto -- add test.kdbx --title Mail --user alice --url https://mail.example --password
npm run proto -- ls test.kdbx                        # zeigt nie Passwörter
npm run proto -- show test.kdbx Mail                 # geschützte Felder (Passwort immer) als ******
npm run proto -- show test.kdbx Mail --reveal        # … im Klartext
npm run proto -- set test.kdbx Mail Notes "Testnotiz"
npm run proto -- set test.kdbx Mail Password -       # "-" = verdeckt abfragen (Pflicht für geschützte Felder)
npm run proto -- set test.kdbx Mail PIN - --protect  # eigenes geschütztes Feld
npm run proto -- attach test.kdbx Mail ./rechnung.pdf
npm run proto -- rm test.kdbx Mail                   # in den Papierkorb; dort erneut: endgültig
npm run proto -- repair-times test.kdbx              # Zeitstempel aus der Zukunft reparieren (siehe unten)
```

Die Datei lässt sich jederzeit mit KeePassXC öffnen. Die lokale Datei wird **atomar**
geschrieben (erst in eine temporäre Datei, dann umbenannt): Ein Absturz hinterlässt nie eine
halbe Datei. Unter Windows wiederholt die Kommandozeile das Umbenennen gut 3 s lang, wenn ein
Virenscanner, der Suchindex oder OneDrive die Datei gerade kurz festhält (`EPERM`/`EBUSY`).

**Windows:** Die Beispiele sind für bash geschrieben. In **PowerShell** oder **cmd** laufen die
`npm run proto -- …`-Zeilen genau so; nur Variablen schreibt man anders (siehe unten). In
**Git Bash** älterer Git-for-Windows-Versionen (vor 2.54, ohne „Pseudo Console“) bekommt Node
kein Terminal: Dann ist eine Passwort-Eingabe **sichtbar** (die Kommandozeile warnt davor).
Abhilfe: Git for Windows aktualisieren, PowerShell/cmd benutzen, `winpty npm run proto -- …`
schreiben oder das Passwort über die Umgebungsvariable übergeben.

**Zwei Clients über WebDAV** (z. B. „Vivaldi“ und „Chrome“, je eigene lokale Datei, am besten
je ein eigenes Gerätepasswort):

```bash
URL=https://magentacloud.de/remote.php/webdav/Ownwarden-Test/test.kdbx
npm run proto -- init vivaldi.kdbx                                       # erster Client: neue Datenbank
npm run proto -- add vivaldi.kdbx --title Mail --user alice
npm run proto -- sync vivaldi.kdbx --url $URL --user name@t-online.de   # legt die Datei auf dem Server an
npm run proto -- sync chrome.kdbx  --url $URL --user name@t-online.de   # chrome.kdbx fehlt: Server-Fassung holen
npm run proto -- set chrome.kdbx Mail UserName alice2
npm run proto -- sync chrome.kdbx  --url $URL --user name@t-online.de   # hochladen
npm run proto -- sync vivaldi.kdbx --url $URL --user name@t-online.de   # Vivaldi übernimmt die Änderung
```

Dasselbe in PowerShell (in cmd: `set URL=…` und `%URL%`):

```powershell
$URL = "https://magentacloud.de/remote.php/webdav/Ownwarden-Test/test.kdbx"
npm run proto -- sync chrome.kdbx --url $URL --user name@t-online.de
```

Den ersten Client mit `init` anlegen und hochladen; weitere Clients mit `sync` ohne lokale
Datei starten (sie holen dann die Server-Fassung, mit demselben Master-Passwort). Gibt es
weder die lokale Datei noch die Datei auf dem Server, bricht `sync` mit einem Hinweis auf
`init` ab. Zwei unabhängig mit `init` angelegte Datenbanken sind zwei verschiedene Tresore
(verschiedene Wurzelgruppen): `sync` führt sie **nicht** zusammen, sondern bricht ab, ohne etwas
zu schreiben. Nur wer das wirklich will, hängt `--merge-different-vault` an – dann werden beide
zu einem vereinigt (der Kern selbst behandelt verschiedene Wurzeln als dieselbe Gruppe,
`../spec/README.md` 5.2).

**Lokale Sicherungskopien:** Ändert ein Abgleich die lokale Datei inhaltlich, kopiert `sync` die
bisherige Datei vorher nach `ownwarden-local-backups/` neben ihr
(`<Name>.<UTC-Zeit yyyyMMdd-HHmmss-SSS>.kdbx`, Rechte 0600 unter Linux/macOS; die neuesten 10
pro Datei bleiben). Warum: Eine Änderung, die dieses Gerät noch nie hochgeladen hat, steht nur in
der lokalen Datei. Verliert sie beim Zusammenführen – etwa gegen eine neuere Löschung auf einem
anderen Gerät, so ist die Regel –, wäre sie sonst nirgends mehr; die Sicherungen auf dem Server
enthalten nur frühere Server-Fassungen. Entfernt ein Abgleich Einträge, die auf einem anderen
Gerät gelöscht wurden, nennt `sync` sie mit ⚠️. Eine Sicherung öffnet man direkt mit KeePassXC
(gleiches Master-Passwort) und holt sich dort zurück, was fehlt. Abgleiche ohne Änderung legen
keine Sicherung an.

**Geräteuhr und `repair-times`:** Ging die Uhr beim Bearbeiten vor (auch offline, und auch wenn
sie inzwischen wieder stimmt), tragen die Änderungen Zeitstempel aus der Zukunft. `sync`
verweigert dann den Abgleich (`FutureTimestampsError`, es wird nichts geschrieben) und nennt den
Befehl zur Reparatur. Erst die Uhr stellen, dann `npm run proto -- repair-times <datei>`: Jeder
Zeitstempel, der mehr als 2 Minuten nach der Gerätezeit liegt, wird auf „jetzt“ gesetzt (das
Ablaufdatum nie); die bisherige Datei wird vorher lokal gesichert. Die betroffenen Änderungen
gelten danach als eben gemacht – gegen eine danach gemachte Änderung eines anderen Geräts
verlieren sie. Ohne solche Zeitstempel ändert `repair-times` nichts.

`test/readme-commands.test.ts` führt die Befehle dieses Abschnitts und des Servertests genau
so aus, wie sie hier stehen (gegen den WebDAV-Testserver) – nach einer Änderung an der
README also `npx vitest run test/readme-commands.test.ts`.

### Standardwerte des Abgleichs (`DEFAULT_SYNC_SETTINGS`)

| Einstellung | Wert | Bedeutung |
|---|---|---|
| `maxAttempts` | 5 | So oft wird bei `412` (anderes Gerät hat gleichzeitig geschrieben) neu gelesen und zusammengeführt. |
| `maxClockSkewMs` | 2 Minuten | Weicht die Geräteuhr mehr vom `Date`-Header des Servers ab, bricht der Abgleich vor dem Schreiben ab (`ClockSkewError`). Enthält die lokale Datenbank Zeitstempel, die später liegen als Serverzeit + 2 Minuten (beim ersten Hochladen: Gerätezeit + 2 Minuten), bricht er ebenfalls ab (`FutureTimestampsError`, Reparatur mit `restampFutureTimes`). |
| `backupsToKeep` | 20 | Sicherungskopien pro Tresor-Datei im Ordner `ownwarden-backups/` neben der Datei. |

Sicherungskopien auf dem Server: Vor jedem Überschreiben wird die bisherige Fassung kopiert –
**ohne Sicherung wird nie geschrieben** –, und zwar **einmal pro Fassung**: Der Name enthält
eine Kennung aus dem ETag (`<Name>.<UTC yyyyMMdd-HHmmss-SSS>.<12 Hex-Zeichen>.kdbx`, z. B.
`tresor.20261015-171500-042.3f9a0c12d4e5.kdbx`; ältere Namen ohne Kennung werden weiter erkannt).
Scheitern Schreibversuche (423, 5xx, Zeitüberschreitung, 412), entstehen so keine Kopien derselben
Fassung, die ältere, verschiedene Fassungen verdrängen. Aufgeräumt wird erst **nach** einem
erfolgreichen Schreiben, und die Sicherung der eben überschriebenen Fassung bleibt immer. Das
Aufräumen ist „best effort“ (Entscheidung vom 2026-10-16): Lässt sich eine alte Kopie nicht
löschen (z. B. `403`, `423`), läuft der Abgleich trotzdem, und das Ergebnis enthält einen Hinweis
(`SyncResult.warnings`; die Kommandozeile zeigt ihn mit ⚠️). Dann können mehr als 20 Kopien
liegen bleiben. Einen Hinweis gibt es auch, wenn die eben gesicherte Kopie in der Ordnerliste
fehlt (der Server nennt die Dateien z. B. unter einem anderen Pfad): Dann löscht das Aufräumen
nie etwas.

Zeitlimit (`DEFAULT_WEBDAV_TIMEOUT_MS`, 25 s): Es greift bei **Stillstand**, nicht für die ganze
Übertragung – beim Herunterladen setzt jedes empfangene Stück es zurück, beim Hochladen kommt
die Zeit hinzu, die der Inhalt bei 16 KiB/s braucht (`MIN_UPLOAD_BYTES_PER_SECOND`). Große
Tresore scheitern so nicht an langsamen Leitungen. Die Meldungen beginnen mit
„Zeitüberschreitung“ („… Der Server hat nicht innerhalb von 25 s geantwortet“, „… 25 s lang
keine Daten“, beim Hochladen „Zeitüberschreitung bei der Übertragung …“). Unter 30 s liegt der
Wert wegen der Browser-Erweiterung (siehe „Bekannte Grenzen“).

---

## WebDAV-Servertest: MagentaCLOUD und Nextcloud prüfen

Der Servertest prüft Schritt für Schritt, ob ein Server alles kann, worauf sich der sichere
Abgleich verlässt. Er arbeitet nur in einem neuen Unterordner `ownwarden-probe-<zufall>/`
des angegebenen Ordners und löscht ihn am Ende wieder – auch wenn etwas schiefgeht.
**Nur mit einem Test-Zugang bzw. Testordner benutzen.**

### MagentaCLOUD

1. Im Browser bei [magentacloud.de](https://magentacloud.de) anmelden und einen **Testordner**
   anlegen, z. B. `Ownwarden-Test`.
2. In der Web-Oberfläche ein **Gerätepasswort** erzeugen (Einstellungen → Sicherheit bzw.
   „Geräte & Sitzungen“; MagentaCLOUD läuft auf Nextcloud, die Bezeichnungen können je nach
   Version abweichen). Name z. B. „Ownwarden-Test“. Das Passwort wird **nur einmal**
   angezeigt – kurz notieren, nach dem Test widerrufen.
3. Benutzername ist der **Telekom-Login (E-Mail-Adresse)**. Laut Forenberichten klappt WebDAV
   nicht, wenn der Telekom-Login eine externe E-Mail-Adresse ist – dann liefert der Test `401`.
4. Test starten (das Passwort wird verdeckt abgefragt; nicht in die Kommandozeile schreiben):
   ```bash
   cd core
   npm run webdav-probe -- --url https://magentacloud.de/remote.php/webdav/Ownwarden-Test/ --user name@t-online.de --abort-test
   ```
5. Danach das Gerätepasswort in der Web-Oberfläche widerrufen (oder für den nächsten Test
   behalten – aber nie für echte Daten).

### Nextcloud (eigener Server)

1. Testordner anlegen, z. B. `Ownwarden-Test`.
2. **App-Passwort** erzeugen: Persönliche Einstellungen → Sicherheit → „Geräte & Sitzungen“ →
   Namen eingeben → „Neues App-Passwort erstellen“. Bei Zwei-Faktor-Anmeldung ist ein
   App-Passwort Pflicht.
3. Test starten (Adresse mit dem Nextcloud-Benutzernamen; die ältere Form
   `https://<server>/remote.php/webdav/Ownwarden-Test/` geht ebenfalls):
   ```bash
   npm run webdav-probe -- --url https://cloud.example.de/remote.php/dav/files/<benutzer>/Ownwarden-Test/ --user <benutzer> --abort-test
   ```

### Ergebnis lesen

Jede Zeile ist eine Prüfung: ✅ in Ordnung, ⚠️ geht, mit Einschränkung **oder nicht geprüft**,
❌ Problem. Am Ende steht das Gesamtergebnis; Exit-Code 0 = sicher (keine ❌), 1 = nicht sicher,
2 = Bedienfehler. Jede Prüfung macht es wie der echte Abgleich und ist mindestens so streng; ließ
sich etwas nicht prüfen, steht dort ⚠️ „nicht geprüft“ – das ist keine Bestätigung. Die
Hinweise am Ende also immer lesen.

- **Entscheidend** (bei ❌ ist ein sicherer Abgleich nicht gewährleistet): Anlegen mit
  `If-None-Match: *`, GET mit ETag, Schreiben mit aktuellem `If-Match`, **Ablehnen eines
  veralteten `If-Match` mit 412** (sonst könnten zwei Geräte sich gegenseitig Änderungen
  überschreiben), neuer ETag auch bei Änderungen in derselben Sekunde, COPY bzw. Hochladen der
  Sicherungskopie, Sicherungskopien wie beim Abgleich.
- **Neuer ETag in derselben Sekunde**: Der Test schreibt zweimal gleich viel direkt
  hintereinander und prüft über die `Date`-Header, dass beide Schreibvorgänge in **derselben
  Serversekunde** lagen (bis zu 5 Versuche). Gelingt das nie (langsame Leitung) oder fehlt der
  `Date`-Header, heißt das ⚠️ „nicht geprüft“. Bleibt der ETag gleich: ❌.
- **Sicherungskopien wie beim Abgleich**: mit dem Code des Abgleichs (`WebDavAdapter`) – Ordner
  `ownwarden-backups/` anlegen und beim zweiten Mal wiederverwenden (MKCOL auf den vorhandenen
  Ordner muss 201, 405 oder eine Weiterleitung liefern, sonst scheitert jeder Abgleich: ❌),
  zwei Fassungen sichern, die ältere aufräumen. Bleibt danach mehr als eine Kopie liegen,
  versteht das Aufräumen die Ordnerliste des Servers nicht: ⚠️.
- **Schwacher ETag (`W/"…"`)**: ⚠️. Streng normgerechte Server lehnen `If-Match` mit einem
  schwachen ETag ab – dann scheitert jeder Abgleich mit 412. Die folgenden Prüfungen zeigen, ob
  der Server ihn trotzdem annimmt.
- **Date-Header / Uhrzeit**: ⚠️, wenn die Uhr dieses Rechners mehr als 2 Minuten abweicht –
  Ownwarden würde dann nicht schreiben. Uhr stellen und erneut testen.
- **PROPFIND / DELETE**: ⚠️ heißt nur, dass alte Sicherungskopien nicht automatisch gelöscht
  werden; der Abgleich selbst bleibt sicher. Die Ordnerliste muss die Dateien unter genau dem
  angefragten Pfad nennen (wie beim Aufräumen); nennt sie einen anderen Pfad: ⚠️.
- **Abgebrochener Upload** (nur mit `--abort-test`): Der Test lädt wie der echte Abgleich mit
  `Content-Length` hoch (kündigt 512 KiB an), sendet nur 256 KiB und trennt dann die Verbindung.
  ✅ heißt, die alte Fassung blieb unverändert. Das ist **die eigentliche Prüfung** für diesen
  Punkt – der PHP-Testserver der automatischen Tests kann ihn nicht wirklichkeitsgetreu
  nachstellen. Antwortet der Server schon vor dem Abbruch (z. B. 411, 413), kam kein
  abgebrochener Upload bei ihm an: ⚠️ „nicht geprüft“. ❌ heißt: Der Server hat den
  unvollständigen Upload angenommen (2xx) oder die Datei hat sich geändert – ein ernstes Problem
  (eine halb hochgeladene Tresor-Datei).

Läuft der Servertest grün, kann man mit dem Testordner den Abgleich der Kommandozeile
ausprobieren (siehe oben).

---

## Bekannte Grenzen

- **Prototyp – nur für Testdaten.** Nichts davon ist für echte Passwörter gedacht.
- **Nach dem Speichern in KeePassXC schreibt Ownwarden einmal.** KeePassXC formt beim Speichern
  manches um (Zeilenenden CR LF → LF, IconID 0 bei eigenem Icon, sortierte Tags, das
  Standard-AutoType auch in Verlaufseinträgen …). Ownwarden wertet das nicht als Änderung der
  Felder, schreibt beim nächsten Abgleich aber einmal seine eigene Form zurück (inkl.
  aktualisierter Feld-Zeitstempel). Das ist harmlos und endet danach – kein „Ping-Pong“ (geprüft
  in `src/sync/sync.keepassxc.test.ts`). Das gilt auch für den Verlauf: Stehen nach so einem
  Speichern zwei fast gleiche Fassungen im Verlauf, wählen alle Geräte dieselbe
  (`../spec/README.md` 5.1, Testfall 33).
- **Eine reine Umsortierung wird nie hochgeladen.** Ownwarden vergleicht Einträge und Gruppen
  unabhängig von ihrer Reihenfolge; eine andere Reihenfolge allein löst kein Schreiben aus.
- **Schwache ETags** (`W/"…"`) führen bei streng normgerechten Servern dazu, dass jeder Abgleich
  mit 412 scheitert. Der Servertest warnt davor.
- **Abgebrochener Upload**: Die automatischen Tests laufen mit dem eingebauten PHP-Webserver,
  der Uploads vollständig puffert – den Abbruch auf Server-Seite können sie nicht prüfen. Die
  echte Prüfung ist der Servertest mit `--abort-test` gegen MagentaCLOUD/Nextcloud.
- **KeePassXC nicht zum Synchronisieren benutzen** („Datenbank zusammenführen“, automatisches
  Neuladen): KeePassXC übernimmt im Standardmodus keine Löschungen und führt pro Eintrag statt
  pro Feld zusammen (belegt in `test/interop/keepassxc-merge.test.ts`). Öffnen, ändern,
  speichern in KeePassXC ist in Ordnung.
- **KeePassXC ordnet CustomData bei jedem Start anders** (beobachtet mit 2.7.6). Ownwarden
  ignoriert diese Reihenfolge; Vergleiche von KeePassXC-Exporten müssen sie normalisieren.
- `keepassxc-cli show -a <Feld>` zeigt in 2.7.6 auch **geschützte Felder ohne `-s`** im Klartext
  – das ist Verhalten von KeePassXC, nicht von Ownwarden.
- **Aufräumen der Sicherungen ist „best effort“**: Lassen sich alte Kopien nicht löschen, bleiben
  mehr als `backupsToKeep` liegen (mit Hinweis).
- **Sicherungen enthalten auch Gelöschtes.** Die Sicherungen auf dem Server
  (`ownwarden-backups/`) und die lokalen der Kommandozeile (`ownwarden-local-backups/`) sind
  ältere Fassungen der Datei, verschlüsselt mit dem Master-Passwort von damals. Wer einen Eintrag
  endgültig loswerden will, muss auch die Sicherungen löschen.
- **Geräteuhr**: Weicht sie beim Abgleich mehr als 2 Minuten von der Serverzeit ab, verweigert
  Ownwarden den Abgleich (`ClockSkewError`). Ging sie schon beim **Bearbeiten** vor (auch offline,
  auch wenn sie inzwischen wieder stimmt), enthält die lokale Datenbank Zeitstempel aus der
  Zukunft: Auch dann wird nichts hochgeladen (`FutureTimestampsError`, Grenze: Serverzeit + 2
  Minuten, beim ersten Hochladen Gerätezeit + 2 Minuten). Reparatur: `restampFutureTimes` bzw.
  `npm run proto -- repair-times <datei>` – die betroffenen Änderungen gelten danach als „jetzt“
  gemacht und können gegen später gemachte Änderungen anderer Geräte verlieren. Ausnahme:
  Enthält die Datei **auf dem Server** schon solche Zeitstempel (z. B. von KeePassXC auf einem
  Gerät mit falscher Uhr), werden sie hingenommen; die Grenze ist dann deren spätester
  Zeitstempel + 2 Minuten (sonst könnte kein Gerät mehr abgleichen). Geht die Uhr dagegen
  **nach**, gewinnen ältere Änderungen anderer Geräte gegen die eigenen.
- **Felder ohne Feld-Zeitstempel**: Haben **beide** Fassungen eines Eintrags kein
  `Ownwarden.FieldTimes` (z. B. nur in KeePassXC bearbeitet), entscheidet die neuere Fassung
  (ganze Sekunden von `lastModification`) auch, welche Felder fehlen. Ein Feld, das auf der
  älteren Kopie gleichzeitig in KeePassXC neu angelegt wurde, verliert dann (es bleibt im
  Verlauf). Ist nur EINE Seite versiegelt, kann ein in KeePassXC ohne Verlaufseintrag entferntes
  Feld über eine versiegelte Kopie zurückkommen. Ein entfernter Wert bleibt immer im Verlauf des
  Ergebnisses – auch wenn man den Verlauf in KeePassXC gelöscht hat, bringt ihn ein Gerät mit
  älterer Kopie wieder in den Verlauf (nicht in die aktuelle Fassung). Einzelheiten:
  `../spec/README.md` Abschnitt 10.
- **Zeichen, die KDBX nicht speichern kann, werden abgelehnt** (nie still verändert):
  Steuerzeichen außer Tab/LF/CR, U+FFFE, U+FFFF und einzelne UTF-16-Surrogate in ungeschütztem
  Text, in geschützten Werten nur einzelne Surrogate. Die Bearbeiten-Funktionen (`createEntry`,
  `setField`, `editEntry`, `setAttachment`, `setTags`, `createGroup`, `renameGroup` …) und
  `createNewVault` (Datenbankname) werfen dann einen `RangeError` mit deutscher Meldung, die den
  Wert nicht nennt. Der spätere
  Bitwarden-Import muss solche Einträge melden oder nachfragen.
- **Doppelte UUIDs in einer Datei** (in der KeePass-Welt gibt es solche Dateien): Beim Lesen
  bekommt jedes spätere Vorkommen einer Gruppen- oder Eintrags-UUID eine abgeleitete neue UUID
  (auf jedem Gerät dieselbe, `../spec/README.md` 5.2); es geht nichts verloren. Verweise auf die
  alte UUID (Papierkorb, `{REF:…}`) meinen weiter das erste Vorkommen. In der Datei steht die neue
  UUID erst nach dem nächsten Speichern; ist beim Abgleich nichts zu schreiben, bleibt die Datei
  auf dem Server noch eine Weile so (harmlos, jedes Gerät leitet dasselbe ab). KeePassXC 2.7.6
  legt solche Einträge dagegen still zu einem zusammen.
- **Zwei verschiedene Datenbanken**: Der Kern behandelt verschiedene Wurzelgruppen als dieselbe
  und würde zwei unabhängig angelegte Datenbanken mit gleichem Master-Passwort vereinigen. Die
  Kommandozeile verweigert das (außer mit `--merge-different-vault`); die Erweiterung muss das
  ebenso prüfen. Nach so einer Vereinigung trägt das Ergebnis die kleinere der beiden
  Wurzel-UUIDs: Ein anderes Gerät, dessen lokale Datei noch die andere Wurzel hat, braucht dann
  beim nächsten `sync` ebenfalls einmal `--merge-different-vault`.
- **Schlüsselableitung (Argon2) hat eine Obergrenze**: Ownwarden öffnet keine Datei, deren
  Argon2-Speicher in KiB × Durchläufe größer als 2^25 ist (`KDF_LIMITS` in
  `src/kdbx/constants.ts`); `readKdbx` meldet dann `UnsupportedKdf`, und der Abgleich steht auf
  ALLEN Ownwarden-Geräten, bis die Einstellung gesenkt ist. Erlaubt sind z. B. 64 MiB × 512,
  1 GiB × 32 oder 1 MiB × 32768 (Ownwarden selbst: 64 MiB × 3). Vorsicht mit KeePassXC: Es stellt
  die Parallelität auf die Zahl der Prozessor-Threads und misst die gewählte
  „Entschlüsselungszeit“ mit allen Threads; Ownwarden (hash-wasm) rechnet alle Spuren auf EINEM
  Thread. Was in KeePassXC N Sekunden dauert, kann in Ownwarden bis zu Parallelität × N Sekunden
  dauern, und auf Rechnern mit vielen Threads kann schon die Einstellung „5 s“ bei 64 MiB über
  512 Durchläufe und damit über die Grenze kommen. Gemessen 2026-10 auf einer VM mit 4 vCPU,
  Argon2id 64 MiB: KeePassXC 48,5 ms je Durchlauf bei Parallelität 1 und 19,2 ms bei 4 (5 s ≈ 260
  Durchläufe), hash-wasm 75 ms (512 Durchläufe ≈ 38 s – mehr als die ~30 s, die der Service Worker
  der Erweiterung hat). Auf Rechnern mit 8–16 Threads nur geschätzt, nicht gemessen. Rat: In
  KeePassXC die Entschlüsselungszeit bei etwa 1 s lassen oder die Durchläufe von Hand so setzen,
  dass KiB × Durchläufe deutlich unter 2^25 bleibt (bei 64 MiB höchstens etwa 64–128, wenn die
  Erweiterung schnell bleiben soll).
- **Veränderter Datei-Kopf**: Die Prüfsumme des KDBX-Kopfs ist ohne Schlüssel. Wer Schreibrecht
  im WebDAV-Ordner hat, kann deshalb OHNE das Passwort die Schlüsselableitung auf das erlaubte
  Maximum stellen (Argon2 bis 2 GiB Speicher und 2^25 KiB × Durchläufe, etwa 1 min auf einem
  Thread, oder AES-KDF bis INT_MAX−1 Runden, etwa 85 s). Jedes Entsperren bzw. jeder Abgleich
  rechnet dann erst die ganze Ableitung und scheitert danach an der HMAC-Prüfung mit
  `InvalidCredentials` („Falsches Passwort oder falsche Schlüsseldatei“, Kommandozeile: „Falsches
  Master-Passwort (oder falsche Datei).“) – obwohl die Datei verändert wurde; jeder neue Versuch
  kostet wieder die volle Zeit, und 2 GiB WebAssembly-Speicher können den Service Worker der
  Erweiterung beenden. Diese Mehrdeutigkeit steckt in KDBX selbst (KeePassXC verhält sich
  genauso). Geplant für die Erweiterung: die zuletzt erfolgreich geprüften KDF-Parameter je
  Tresor merken; weichen sie ab und scheitert die HMAC-Prüfung, „Datei wurde verändert oder neu
  verschlüsselt“ melden; vor einer viel teureren Ableitung als der letzten nachfragen.
- **Geschützter Wert in einem unbekannten Element**: Enthält ein XML-Element, das Ownwarden
  nicht kennt (z. B. Daten eines Plugins in Meta oder einem Eintrag), einen geschützten Wert
  (`Protected="True"`), dessen Klartext kein gültiges UTF-8 ist, lehnt Ownwarden die ganze Datei
  ab (`KdbxError` `Corrupt`, „Geschützter Wert in <…>: kein gültiges UTF-8.“). Daten gehen dabei
  nicht verloren (der Abgleich bricht ab), aber kein Ownwarden-Gerät kann die Datei öffnen.
  Bekannte KDBX4-Programme schreiben so etwas nicht (KeePass 2.x verwirft unbekannte Elemente
  beim Laden, KeePassXC überspringt sie); geschützte Anhänge sind nicht betroffen.
- **Browser-Erweiterung, Service Worker**: Chrome beendet ihn, wenn eine Antwort länger als
  30 s braucht. Das Zeitlimit gegen Stillstand (25 s) beendet hängende Anfragen vorher mit einer
  klaren Meldung. Ein großer Upload auf langsamer Leitung (z. B. ein Tresor von einigen MB mit
  Anhängen) kann aber trotzdem länger dauern, bis die Antwort kommt; dann bricht der Abgleich
  ohne Meldung ab. Die Daten bleiben sicher (geschrieben wird nur bedingt), aber die Erweiterung
  muss solche Abgleiche außerhalb des Service Workers machen (z. B. in einer Erweiterungsseite
  oder einem Offscreen-Dokument).
- **Interop-Tests ohne Werkzeuge**: Ohne `keepassxc-cli` bzw. PHP werden die betroffenen Tests
  übersprungen, und `npm test` meldet trotzdem Erfolg. Als Nachweis zählt nur ein Lauf mit
  `OWNWARDEN_REQUIRE_TOOLS=1` (siehe „Tests laufen lassen“).
- **Papierkorb**: Löschen zwei Geräte offline zum ersten Mal etwas, legt jedes einen eigenen
  Papierkorb an; nach dem Abgleich ist einer davon eine normale Gruppe „Papierkorb“ (bei
  KeePassXC ebenso möglich).
- **Kommandozeile**: Zwei gleichzeitig laufende Befehle auf DERSELBEN lokalen Datei können sich
  gegenseitig eine Änderung überschreiben (die Datei bleibt aber immer lesbar). Keine
  Schlüsseldateien. Die Rechte 0600 der lokalen Datei und ihrer Sicherungen wirken nur unter
  Linux/macOS; unter Windows erbt die Datei die Zugriffsrechte des Ordners. In Git Bash älterer
  Git-for-Windows-Versionen ist die Passwort-Eingabe sichtbar (siehe „Die Kommandozeile
  ausprobieren“).
- Zeiten in der Datei sind nur sekundengenau (KDBX); Feld-Zeitstempel sind millisekundengenau.
