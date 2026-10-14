# Ownwarden – Project Context

## Projekt
Ownwarden ist ein selbst gebauter Passwortmanager als Ersatz für Bitwarden. Der Nutzer bestimmt selbst, wo die
verschlüsselte Datenbank liegt und worüber sie synchronisiert wird. Es gibt keinen eigenen Server. Der Code soll für
den Nutzer lesbar und selbst reparierbar sein.

## Zielplattformen (in dieser Reihenfolge)
1. **Windows-PC:** Browser-Erweiterung für Vivaldi und Google Chrome (Chromium, Manifest V3). Arbeitet eigenständig,
   ohne Desktop-App.
2. **Android-Smartphone:** native App (Kotlin) mit Autofill in Apps und Browsern (Autofill Framework) und
   Passkey-Anbieter (Credential Manager, ab Android 14).
3. **Später:** iPad Pro (M1, iPadOS) mit Autofill- und Passkey-Anbieter (Swift).

Nicht geplant: Teilen/Organisationen, Send, Notfallzugriff, Web-Vault, eigener Sync-Server.

## Funktionsumfang Version 1
- Eintragstypen: Login (Benutzername, Passwort, URIs, TOTP, Notizen, eigene Felder), Passkey, sichere Notiz, Karte,
  Identität. Ordner, Favoriten, Suche.
- Passwort- und Passphrasen-Generator, TOTP-Anzeige.
- Autofill im Browser: Inline-Menü, Kontextmenü, Tastenkürzel, Speichern/Aktualisieren-Abfrage bei neuen Logins.
- Autofill auf Android in Apps und Browsern.
- Passkeys erstellen, speichern und verwenden (Browser und Android).
- Sperren mit Zeitlimit, Entsperren per Master-Passwort (Android zusätzlich Biometrie).
- Import des Bitwarden-JSON-Exports, Export.

## Getroffene Entscheidungen (Council, 2026-10-14)
- **Eigene Codebasis.** Kein Fork der Bitwarden-Clients, kein Vaultwarden.
- **Dateiformat KDBX4** (KeePass). Gründe: Notausgang (KeePassXC, KeePassDX und Strongbox öffnen dieselbe Datei),
  Referenz zum Testen, bringt Eintrags-UUIDs, Zeitstempel, Lösch-Liste und Verlauf mit.
  Passkeys im KeePassXC-Attributschema (`KPEX_PASSKEY_*`). Karten/Identitäten als Einträge mit Feldern und
  Typ-Markierung in den Eintrags-Zusatzdaten (CustomData).
- **Kein gemeinsamer Rust-Kern.** TypeScript für die Erweiterung, Kotlin für Android, später Swift für das iPad.
  Das Dateiformat ist der Vertrag; gemeinsame Referenzdateien und Merge-Testfälle in `spec/` müssen von allen
  Implementierungen bestanden werden.
- **Keine selbst gebaute Kryptografie.** Nur Plattform-APIs (WebCrypto, Android JCA/Keystore) und etablierte
  Bibliotheken (z. B. für Argon2). Auswahl im Prototyp.
- **Speicher Version 1:** eine WebDAV-Anbindung für Nextcloud und MagentaCLOUD
  (`https://magentacloud.de/remote.php/webdav`, App-Passwort). Lokale Datei nur für Tests und Export.
  OneDrive, Google Drive und Dropbox sind nicht geplant.
- **Übergang:** Bitwarden bleibt bis Version 1 in Benutzung. Ownwarden arbeitet bis dahin nur mit Testdaten;
  der Umzug erfolgt einmal per Bitwarden-JSON-Export.

## Sync-Regel: neueste Änderung gewinnt – pro Feld
- Jedes Feld eines Eintrags hat einen eigenen Änderungszeitstempel, gespeichert in den Zusatzdaten (CustomData) des
  Eintrags. Beim Zusammenführen gewinnt pro Feld der neuere Zeitstempel.
- Die überschriebene Fassung eines Eintrags wandert in dessen Verlauf (History). Nichts geht endgültig verloren.
- Einträge, die ein anderes Programm (z. B. KeePassXC) geändert hat, haben keine Feld-Zeitstempel: geänderte Felder
  erhalten dann die Änderungszeit des Eintrags.
- Löschen: Lösch-Liste (DeletedObjects) mit Zeitstempel. Löschen gegen Ändern: das Neuere gewinnt.
- Schreiben: nur bedingt (WebDAV `If-Match` mit ETag). Hat sich die Datei geändert: neu laden, zusammenführen, erneut
  schreiben. Vor jedem Schreiben ein Backup der vorherigen Fassung.
- Uhren: Neue Zeitstempel nie kleiner als der größte bekannte Zeitstempel + 1 ms; bei deutlicher Abweichung warnen.

## Sicherheitsregeln
- Domain-Abgleich mit Public Suffix List; kein automatisches Ausfüllen in fremden iframes oder auf HTTP-Seiten ohne
  Bestätigung; Schutz gegen Clickjacking (unsichtbare Overlays).
- Android: App-zu-Domain-Zuordnung über Digital Asset Links; Passkey-Anfragen von Browsern nur aus einer
  Freigabeliste mit Signaturprüfung.
- Passkey-Signaturzähler bleibt 0 (wie bei synchronisierten Passkeys üblich).
- Ownwarden schreibt die echte Datenbank erst, wenn die Merge-Tests gegen KeePassXC-Dateien grün sind.

## Aktuelle Phase
Phase 0 – Planung und Wegwerf-Prototypen. Das Repo enthält noch keinen Anwendungscode.

## Geplante Repo-Struktur
- `spec/` – Formatnotizen, Referenz-KDBX-Dateien (mit KeePassXC erzeugt), Merge-Testfälle
- `extension/` – Browser-Erweiterung (TypeScript, Manifest V3)
- `android/` – Android-App (Kotlin)
- `docs/adr/` – Architekturentscheidungen

## Roadmap
0. **Prototypen:**
   - KDBX4 lesen/schreiben in TypeScript gegen KeePassXC-Dateien; prüfen, dass KeePassXC die Feld-Zeitstempel in
     CustomData beim Speichern erhält.
   - WebDAV gegen Nextcloud und MagentaCLOUD: ETag und bedingtes Schreiben (`If-Match`) funktionieren?
   - Manifest-V3-Erweiterung: Entsperren, Schlüssel in `chrome.storage.session`, Autofill auf einer Testseite.
   - Passkeys im Browser über das Abfangen von `navigator.credentials` (Test z. B. gegen webauthn.io).
   - Android: Autofill- und Credential-Provider-Grundgerüst.
1. TypeScript-Kern: KDBX4, Feld-Merge, WebDAV-Anbindung, Merge-Testfälle.
2. Browser-Erweiterung für Vivaldi/Chrome: Tresor, Autofill, Passkeys, Generator, Bitwarden-Import.
3. Android-App: Tresor, Autofill, Passkeys, Sync – besteht dieselben Testfälle aus `spec/`.
4. Umzug von Bitwarden.
5. iPad.

## Offene Punkte
- Verteilung der Erweiterung: Chrome Web Store (nicht gelistet) oder Entwicklermodus.
- Verteilung der Android-App: eigene signierte APK (Sideload) oder Store.
- Build-Werkzeuge und UI-Toolkits (im Prototyp festlegen).

## Definition of Done (Version 1)
- Auf Windows (Vivaldi und Chrome) und Android: Passwörter und Passkeys per Autofill nutzbar.
- Sync über Nextcloud und MagentaCLOUD ohne Datenverlust. Testfälle grün für: gleichzeitige Änderung verschiedener
  Felder, Löschen gegen Ändern, Offline-Gerät, falsch gehende Geräteuhr, abgebrochener Upload.
- Die Datei lässt sich jederzeit mit KeePassXC öffnen; Änderungen aus KeePassXC werden korrekt übernommen.
- Import des Bitwarden-JSON-Exports funktioniert.
- Der Code ist dokumentiert und für den Nutzer nachvollziehbar.
