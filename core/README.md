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
- **Feld-Merge** („neueste Änderung gewinnt – pro Feld“) mit eigenen Feld-Zeitstempeln
  (`Ownwarden.FieldTimes` im CustomData jedes Eintrags). Änderungen aus KeePassXC werden
  erkannt – genau die geänderten Felder bekommen die Änderungszeit von KeePassXC.
  Löschen gegen Ändern, Papierkorb, verschobene Einträge, gelöschte Gruppen
  (Wiederherstellungsgruppe), Verlauf beider Seiten.
- **WebDAV-Abgleich**: nur bedingtes Schreiben (`If-Match`/`If-None-Match: *`), bei `412`
  neu lesen und zusammenführen, vor jedem Überschreiben eine Sicherungskopie, Prüfung der
  Geräteuhr gegen den Server.
- **Kommandozeile** `npm run proto` zum Ausprobieren (siehe unten) und der
  **WebDAV-Servertest** `npm run webdav-probe` für MagentaCLOUD und Nextcloud.

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
| `src/kdbx/settings.ts`, `constants.ts`, `bytes.ts`, `compression.ts`, `variant-dictionary.ts` | Standardwerte, Konstanten, Hilfsfunktionen. |
| **merge/** | |
| `src/merge/merge.ts` | `mergeVaults`: Ablauf des Zusammenführens (Einträge, Gruppen, Löschungen, Meta). |
| `src/merge/merge-entry.ts`, `merge-group.ts`, `merge-meta.ts`, `history.ts` | Einzelne Einträge, Gruppen, Meta-Angaben, Verlauf zusammenführen. |
| `src/merge/fields.ts`, `field-times.ts`, `encoding.ts` | Was ein „Feld“ ist; `Ownwarden.FieldTimes` lesen/schreiben; Erkennung externer Änderungen. |
| `src/merge/clock.ts` | Monotone Uhr: neue Zeitstempel sind immer die neuesten. |
| `src/merge/vault-ops.ts` | **Der einzige Weg, Einträge zu ändern** (anlegen, Feld setzen, Anhang, Passkey, verschieben, löschen …). |
| **sync/** | |
| `src/sync/sync.ts` | `syncVault`: lesen → Uhr prüfen → zusammenführen → sichern → bedingt schreiben; `DEFAULT_SYNC_SETTINGS`. |
| `src/sync/webdav.ts` (+ `http.ts`, `multistatus.ts`, `backup-names.ts`) | `WebDavAdapter`: GET/PUT mit ETags, Sicherungskopien, Aufräumen. |
| `src/sync/kdbx-codec.ts` | Verbindet Sync und Datei (`readKdbx`/`writeKdbx` mit Master-Passwort). |
| `src/sync/vault-equal.ts` | „Inhaltlich gleich?“ – verhindert unnötiges Hochladen. |
| `src/sync/memory-adapter.ts` | Speicher im Arbeitsspeicher (Tests, Ausprobieren ohne Server). |
| **cli/** (nur Node) | |
| `src/cli/ownwarden-proto.ts` (+ `prompt.ts`, `atomic-file.ts`) | Prototyp-Kommandozeile. |
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

Voraussetzungen: Node ≥ 22. Für einen Teil der Tests außerdem **KeePassXC 2.7** (Programm
`keepassxc-cli`) sowie **PHP ≥ 8.1 mit Composer** (WebDAV-Testserver). Fehlt eines davon,
werden die betroffenen Tests übersprungen (nicht als Fehler gezählt).

```bash
cd core
npm install                 # einmalig
npm test                    # alle Tests (ca. 30 s)
npx vitest run test/e2e     # nur einen Ordner oder eine Datei
npm run typecheck           # TypeScript-Prüfung (tsc --noEmit)
```

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
```

Die Datei lässt sich jederzeit mit KeePassXC öffnen. Die lokale Datei wird **atomar**
geschrieben (erst in eine temporäre Datei, dann umbenannt): Ein Absturz hinterlässt nie eine
halbe Datei.

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

Den ersten Client mit `init` anlegen und hochladen; weitere Clients mit `sync` ohne lokale
Datei starten (sie holen dann die Server-Fassung, mit demselben Master-Passwort). Gibt es
weder die lokale Datei noch die Datei auf dem Server, bricht `sync` mit einem Hinweis auf
`init` ab. Zwei unabhängig mit `init` angelegte Datenbanken sind zwei verschiedene Tresore.

`test/readme-commands.test.ts` führt die Befehle dieses Abschnitts und des Servertests genau
so aus, wie sie hier stehen (gegen den WebDAV-Testserver) – nach einer Änderung an der
README also `npx vitest run test/readme-commands.test.ts`.

### Standardwerte des Abgleichs (`DEFAULT_SYNC_SETTINGS`)

| Einstellung | Wert | Bedeutung |
|---|---|---|
| `maxAttempts` | 5 | So oft wird bei `412` (anderes Gerät hat gleichzeitig geschrieben) neu gelesen und zusammengeführt. |
| `maxClockSkewMs` | 2 Minuten | Weicht die Geräteuhr mehr vom `Date`-Header des Servers ab, bricht der Abgleich vor dem Schreiben ab (`ClockSkewError`). |
| `backupsToKeep` | 20 | Sicherungskopien pro Tresor-Datei im Ordner `ownwarden-backups/` neben der Datei. |

Sicherungskopien: Vor jedem Überschreiben wird die bisherige Fassung kopiert – **ohne
Sicherung wird nie geschrieben**. Das Aufräumen alter Kopien ist dagegen „best effort“
(Entscheidung vom 2026-10-16): Lässt sich eine alte Kopie nicht löschen (z. B. `403`, `423`),
läuft der Abgleich trotzdem, und das Ergebnis enthält einen Hinweis (`SyncResult.warnings`;
die Kommandozeile zeigt ihn mit ⚠️). Dann können mehr als 20 Kopien liegen bleiben.

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

Jede Zeile ist eine Prüfung: ✅ in Ordnung, ⚠️ geht, mit Einschränkung, ❌ Problem.
Am Ende steht das Gesamtergebnis; Exit-Code 0 = sicher, 1 = nicht sicher, 2 = Bedienfehler.

- **Entscheidend** (bei ❌ ist ein sicherer Abgleich nicht gewährleistet): Anlegen mit
  `If-None-Match: *`, GET mit ETag, Schreiben mit aktuellem `If-Match`, **Ablehnen eines
  veralteten `If-Match` mit 412** (sonst könnten zwei Geräte sich gegenseitig Änderungen
  überschreiben), neuer ETag auch bei Änderungen in derselben Sekunde, COPY bzw. Hochladen der
  Sicherungskopie.
- **Schwacher ETag (`W/"…"`)**: ⚠️. Streng normgerechte Server lehnen `If-Match` mit einem
  schwachen ETag ab – dann scheitert jeder Abgleich mit 412. Die folgenden Prüfungen zeigen, ob
  der Server ihn trotzdem annimmt.
- **Date-Header / Uhrzeit**: ⚠️, wenn die Uhr dieses Rechners mehr als 2 Minuten abweicht –
  Ownwarden würde dann nicht schreiben. Uhr stellen und erneut testen.
- **PROPFIND / DELETE**: ⚠️ heißt nur, dass alte Sicherungskopien nicht automatisch gelöscht
  werden; der Abgleich selbst bleibt sicher.
- **Abgebrochener Upload** (nur mit `--abort-test`): ✅ heißt, ein mitten im Hochladen
  abgebrochener Upload ließ die alte Fassung unverändert. Das ist **die eigentliche Prüfung**
  für diesen Punkt – der PHP-Testserver der automatischen Tests kann ihn nicht nachstellen.
  ❌ wäre ein ernstes Problem (eine halb hochgeladene Tresor-Datei).

Läuft der Servertest grün, kann man mit dem Testordner den Abgleich der Kommandozeile
ausprobieren (siehe oben).

---

## Bekannte Grenzen

- **Prototyp – nur für Testdaten.** Nichts davon ist für echte Passwörter gedacht.
- **Nach dem Speichern in KeePassXC schreibt Ownwarden einmal.** KeePassXC formt beim Speichern
  manches um (Zeilenenden CR LF → LF, IconID 0 bei eigenem Icon, sortierte Tags …). Ownwarden
  wertet das nicht als Änderung der Felder, schreibt beim nächsten Abgleich aber einmal seine
  eigene Form zurück (inkl. aktualisierter Feld-Zeitstempel). Das ist harmlos und endet
  danach – kein „Ping-Pong“ (geprüft in `src/sync/sync.keepassxc.test.ts`).
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
- **Geräteuhr**: Weicht sie mehr als 2 Minuten von der Serverzeit ab, verweigert Ownwarden den
  Abgleich (statt mit falschen Zeitstempeln zu schreiben).
- **Papierkorb**: Löschen zwei Geräte offline zum ersten Mal etwas, legt jedes einen eigenen
  Papierkorb an; nach dem Abgleich ist einer davon eine normale Gruppe „Papierkorb“ (bei
  KeePassXC ebenso möglich).
- **Kommandozeile**: Zwei gleichzeitig laufende Befehle auf DERSELBEN lokalen Datei können sich
  gegenseitig eine Änderung überschreiben (die Datei bleibt aber immer lesbar). Keine
  Schlüsseldateien.
- Zeiten in der Datei sind nur sekundengenau (KDBX); Feld-Zeitstempel sind millisekundengenau.
