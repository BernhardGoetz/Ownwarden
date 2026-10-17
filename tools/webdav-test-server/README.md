# WebDAV-Testserver (nur für Tests)

Ein kleiner WebDAV-Server auf Basis von [SabreDAV](https://sabre.io/dav/) – derselben Bibliothek,
auf der auch Nextcloud (und damit MagentaCLOUD) aufbaut. Er bildet das Verhalten von Nextcloud
beim Schreiben nach, damit die Tests von Ownwarden (`core/src/sync/`, `core/src/cli/webdav-probe.ts`)
ohne echten Cloud-Zugang laufen.

**Nicht für echte Daten gedacht.** Er läuft mit dem eingebauten PHP-Webserver, nur auf
`127.0.0.1`, ohne HTTPS, mit einem einzigen Testbenutzer.

## Was wie bei Nextcloud funktioniert

| Verhalten | Warum Ownwarden das braucht |
|---|---|
| **Starke ETags, die sich bei jedem Schreiben ändern** – auch bei zwei Schreibvorgängen in derselben Sekunde und bei gleichem Inhalt (Zufallskennung pro Fassung, wie der Datei-Cache von Nextcloud). | Ownwarden schreibt nur mit `If-Match: <ETag>`. Ein ETag aus Größe + Änderungszeit (Sekunden) würde zwei schnelle Änderungen nicht unterscheiden – eine ginge still verloren. |
| **`If-Match` und `If-None-Match: *`** werden ausgewertet (das macht SabreDAV selbst): veralteter ETag → `412`, zweites Anlegen → `412`, `If-Match` auf fehlende Datei → `412`. | Grundlage des sicheren Abgleichs („412 → neu laden, zusammenführen, erneut schreiben“). |
| **Schreiben über Temporärdatei + `rename()`**: Hochgeladene Daten landen erst in einer Temporärdatei; nur wenn alles angekommen ist (Länge passt zu `Content-Length`), ersetzt sie die alte Datei atomar. | Ein abgebrochener Upload darf die Tresor-Datei nicht beschädigen. |
| **Neuer ETag in der PUT-Antwort**, sowohl als `ETag` als auch als `OC-ETag`. | Ownwarden merkt sich den ETag seiner eigenen Fassung. |
| **`Date`-Header** in jeder Antwort. | Ownwarden prüft damit die Geräteuhr. |
| `MKCOL`, `COPY`, `PROPFIND`, `DELETE` | Sicherungskopien im Ordner `ownwarden-backups/` anlegen und aufräumen. |
| **Basic-Auth** mit einem Testbenutzer. | Wie App-/Gerätepasswörter bei Nextcloud und MagentaCLOUD. |

Nicht nachgebildet: Papierkorb, Versionen, die Chunked-Upload-API von Nextcloud, Freigaben,
Sperren (`LOCK`).

Hinweis: Der eingebaute PHP-Webserver liest den kompletten Anfrage-Körper, bevor er `server.php`
startet. Ein abgebrochener Upload erreicht das Skript also gar nicht. Temporärdatei und `rename()`
schützen zusätzlich, falls das Skript einmal hinter einem anderen Webserver läuft.

## Benutzung in Tests

Die Tests starten den Server selbst über `core/test/helpers/webdav-server.ts`
(`startWebDavTestServer()`): freier Port, eigener Datenordner unter `core/test/.tmp/`, zufälliges
Testpasswort. Fehlt der Ordner `vendor/`, führt die Hilfe einmal `composer install` aus. Sind PHP
oder Composer nicht installiert, werden die Tests übersprungen – außer mit
`OWNWARDEN_REQUIRE_TOOLS=1` (strenger Modus, siehe `core/README.md`): Dann ist das ein Fehler.

Voraussetzungen: PHP ≥ 8.1 mit den Erweiterungen `dom`, `xmlreader`, `xmlwriter`, `simplexml`,
`mbstring`, `ctype`, `iconv`; Composer.

## Von Hand starten

```sh
cd tools/webdav-test-server
composer install
mkdir -p data/files
OWNWARDEN_WEBDAV_DATA_DIR="$PWD/data/files" \
OWNWARDEN_WEBDAV_USER=test OWNWARDEN_WEBDAV_PASSWORD=test-passwort \
php -S 127.0.0.1:8080 server.php
```

Danach z. B. den WebDAV-Servertest von Ownwarden darauf loslassen (im Ordner `core/`):

```sh
OWNWARDEN_WEBDAV_PASSWORD=test-passwort npx tsx src/cli/webdav-probe.ts --url http://127.0.0.1:8080/ --user test --abort-test
```

Umgebungsvariablen:

| Variable | Bedeutung |
|---|---|
| `OWNWARDEN_WEBDAV_DATA_DIR` | Pflicht. Wurzel des WebDAV-Baums. |
| `OWNWARDEN_WEBDAV_USER`, `OWNWARDEN_WEBDAV_PASSWORD` | Pflicht. Zugangsdaten des Testbenutzers. |
| `OWNWARDEN_WEBDAV_STATE_DIR` | Optional. Verwaltungsdaten (ETags, Sperre, halbe Uploads). Standard: `<DATA_DIR>.state`. Muss im selben Dateisystem liegen wie `DATA_DIR`, sonst ist `rename()` nicht atomar. |

Der Ordner `data/` und `vendor/` stehen in `.gitignore`; mit `data/files` als Datenordner landen
auch die Verwaltungsdaten (`data/files.state`) dort.
