# Ownwarden – Project Context

## Projekt
Ownwarden ist ein selbst gebauter Passwortmanager als Ersatz für Bitwarden. Der Nutzer bestimmt selbst, wo die
verschlüsselte Datenbank liegt und worüber sie synchronisiert wird. Es gibt keinen eigenen Server. Der Code soll für
den Nutzer lesbar und selbst reparierbar sein.

## Zielplattformen (in dieser Reihenfolge)
1. **Windows-PC:** Browser-Erweiterung für Vivaldi und Google Chrome (Chromium, Manifest V3). Arbeitet eigenständig,
   ohne Desktop-App. Vivaldi und Chrome sind zwei getrennte Clients mit eigener lokaler Kopie und eigenem Zugang.
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
- Offline nutzbar: Jeder Client hält eine verschlüsselte lokale Kopie und synchronisiert, sobald er online ist.
- Dateianhänge an Einträgen (entschieden 2026-10-14).
- Import des Bitwarden-JSON-Exports. Ein eigener Export ist nicht nötig: Die KDBX-Datei ist selbst das Exportformat.

## Getroffene Entscheidungen (Council, 2026-10-14)
- **Eigene Codebasis.** Kein Fork der Bitwarden-Clients, kein Vaultwarden. Fremder Quellcode (z. B. Bitwarden,
  GPL-3.0) dient höchstens als Referenz zum Lesen und wird nicht ins Repo kopiert.
- **Dateiformat KDBX4** (KeePass). Gründe: Notausgang (KeePassXC, KeePassDX und Strongbox öffnen KDBX4-Dateien),
  Referenz zum Testen, bringt Eintrags-UUIDs, Zeitstempel, Lösch-Liste und Verlauf mit.
  Karten/Identitäten als Einträge mit Feldern und Typ-Markierung in den Eintrags-Zusatzdaten (CustomData).
- **Kein gemeinsamer Rust-Kern.** TypeScript für die Erweiterung, Kotlin für Android, später Swift für das iPad.
  Das Dateiformat ist der Vertrag; gemeinsame Referenzdateien und Merge-Testfälle in `spec/` müssen von allen
  Implementierungen bestanden werden.
- **Keine selbst gebaute Kryptografie.** Nur Plattform-APIs und etablierte Bibliotheken. KDBX4 erlaubt als
  Schlüsselableitung Argon2d, Argon2id oder AES-KDF, als Verschlüsselung AES-256, ChaCha20 oder Twofish, und schützt
  Passwortfelder zusätzlich mit einem inneren ChaCha20-Strom. WebCrypto kann weder Argon2 noch ChaCha20 noch AES-ECB
  (für AES-KDF) – dafür braucht die Erweiterung Bibliotheken. Ownwarden schreibt Argon2id + AES-256; welche
  Varianten beim Lesen unterstützt werden (v. a. Twofish), wird im Prototyp entschieden.
- **Speicher Version 1:** eine WebDAV-Anbindung für Nextcloud und MagentaCLOUD (Details unten).
  Die Anbindung „lokale Datei“ nur für Tests. OneDrive, Google Drive und Dropbox sind nicht geplant.
- **Übergang:** Bitwarden bleibt bis Version 1 in Benutzung. Bis zum Umzug arbeitet Ownwarden ausschließlich mit
  Testdateien. Voraussetzung für den Umzug: alle Merge-Testfälle aus `spec/` grün, auch gegen Dateien, die
  KeePassXC verändert hat.

## Sync-Regel: neueste Änderung gewinnt – pro Feld
KDBX speichert Zeitstempel nur pro Eintrag und Gruppe, nicht pro Feld. Ownwarden ergänzt deshalb eigene
Feld-Zeitstempel.

**Was ein „Feld“ ist:** Titel, Benutzername, Passwort, URL, Notizen, jedes eigene Feld (nach Name), Tags, Icon,
Ablaufdatum, Favorit/Typ-Markierung, Elterngruppe, der Passkey (alle `KPEX_PASSKEY_*`-Attribute zusammen als
**eine** Einheit, sonst entstehen kaputte Passkeys) und – falls in Version 1 – jeder Anhang (nach Name).

**Speicherung:** ein einziger CustomData-Eintrag pro Eintrag (z. B. `Ownwarden.FieldTimes`), dessen Wert die
Zeitstempel (in Millisekunden) aller Felder enthält. Nicht die KDBX-4.1-Zeitstempel einzelner CustomData-Einträge
verwenden: KeePassXC verwirft diese beim Speichern und fügt einen eigenen Eintrag `_LAST_MODIFIED` hinzu, der
ignoriert werden muss.

**Regeln:**
- Beim Zusammenführen gewinnt pro Feld der neuere Zeitstempel. Bei Gleichstand entscheidet eine feste,
  deterministische Regel (z. B. bytewiser Vergleich der Werte), damit TypeScript und Kotlin gleich entscheiden.
- KDBX-Zeiten (Eintrag, Löschung) haben nur Sekundengenauigkeit. Beim Vergleich mit Feld-Zeitstempeln wird auf
  Sekunden abgerundet.
- **Entfernte Felder** bekommen einen Lösch-Marker mit Zeitstempel in `Ownwarden.FieldTimes`, sonst taucht das Feld
  beim nächsten Abgleich wieder auf. Umbenennen = Entfernen + Neuanlegen.
- **Änderungen durch andere Programme** (z. B. KeePassXC): Ist die Änderungszeit des Eintrags neuer als sein
  neuester Feld-Zeitstempel, wurde er extern geändert. Welche Felder sich geändert haben, ermittelt Ownwarden durch
  Vergleich mit der zuletzt von ihm geschriebenen Fassung (Verlaufseintrag oder Prüfsumme pro Feld – Verfahren im
  Prototyp festlegen). Diese Felder erhalten die Änderungszeit des Eintrags.
- **Löschen gegen Ändern:** Die Löschzeit (DeletedObjects) wird mit dem neuesten Feld-Zeitstempel der Gegenseite
  verglichen; das Neuere gewinnt. Gewinnt die Änderung, wird die UUID aus DeletedObjects entfernt.
  Nicht jede UUID in DeletedObjects gehört zu einem Eintrag oder einer Gruppe (KeePassXC trägt dort auch gelöschte
  Icons ein). Lösch-Einträge für unbekannte UUIDs bleiben erhalten.
- **Papierkorb:** Löschen in KeePass/KeePassXC verschiebt standardmäßig nur in den Papierkorb. Das ist für Ownwarden
  eine Änderung der Elterngruppe, keine Löschung.
- **Gruppen:** Elterngruppe eines Eintrags ist ein Feld (Zeitstempel: `LocationChanged`). Gruppen selbst werden nach
  denselben Regeln zusammengeführt (Name, Elterngruppe, Löschung). Einträge, deren Gruppe auf einem anderen Gerät
  gelöscht wurde, gehen nicht verloren (Vorschlag: Wiederherstellungsgruppe).
- **Verlauf:** Die überschriebene Fassung jeder Seite kommt in den Verlauf des Eintrags – also bis zu zwei Einträge
  pro Abgleich, wenn beide Geräte verschiedene Felder geändert haben (entschieden 2026-10-15: kein alter Wert soll
  verloren gehen). Verläufe beider Seiten werden nach Zeitstempel (ganze Sekunden) vereinigt und von Doppelten befreit. Die Grenzen aus der
  Datei (`HistoryMaxItems`, `HistoryMaxSize`) gelten, ältere Fassungen fallen also irgendwann heraus. Gewinnt eine
  Löschung, sind die Daten aus der Datei weg und nur noch in Backups.
- **Uhren:** Neue Zeitstempel nie kleiner als der größte bekannte Zeitstempel + 1 ms. Zusätzlich die Gerätezeit gegen
  den `Date`-Header des WebDAV-Servers prüfen; bei deutlicher Abweichung warnen, statt still zu schreiben
  (Schwellwert im Prototyp festlegen).
- **Datenbank-Einstellungen ohne Zeitstempel** (Verschlüsselung, Schlüsselableitung, Kompression,
  `HistoryMaxItems`/`HistoryMaxSize`, übrige Meta-Angaben wie die Beschreibung): Die Fassung der Datei auf dem Server
  gewinnt (entschieden 2026-10-15). Ownwarden ändert diese Einstellungen in Version 1 nicht; so kann ein Gerät mit
  älterer Kopie eine Änderung aus KeePassXC nicht still zurückdrehen.
- **KeePassXC nicht zum Synchronisieren benutzen:** Die Datei in KeePassXC öffnen, ändern und speichern ist in
  Ordnung. Das Zusammenführen von KeePassXC (Datenbank zusammenführen, automatisches Neuladen bei Änderungen)
  arbeitet aber pro Eintrag statt pro Feld und übernimmt Löschungen im Standardmodus nicht – gelöschte Einträge
  kämen zurück.

**Schreiben:**
- Nur bedingt: WebDAV `PUT` mit `If-Match` und dem ETag genau so, wie der Server ihn geliefert hat. Bei `412`: neu
  laden, zusammenführen, erneut schreiben. Die allererste Datei wird mit `If-None-Match: *` angelegt (`If-Match` auf
  eine nicht vorhandene Datei liefert ebenfalls `412`).
- Vor jedem Schreiben ein Backup der vorherigen Fassung (Vorschlag: WebDAV `COPY` in einen Unterordner, die letzten
  N Fassungen behalten; N im Prototyp festlegen).

## Passkeys
- Gespeichert im Attributschema von KeePassXC: `KPEX_PASSKEY_USERNAME`, `KPEX_PASSKEY_CREDENTIAL_ID`,
  `KPEX_PASSKEY_PRIVATE_KEY_PEM` (PKCS#8-PEM), `KPEX_PASSKEY_RELYING_PARTY`, `KPEX_PASSKEY_USER_HANDLE`,
  `KPEX_PASSKEY_FLAG_BE`, `KPEX_PASSKEY_FLAG_BS`, dazu das Tag `Passkey`. Beim Lesen auch die Varianten von Strongbox
  (`KPEX_PASSKEY_GENERATED_USER_ID`, `KPXC_PASSKEY_USERNAME`) und KeePassDX (`KPEX_PASSKEY_PRF`) beachten. Unbekannte
  `KPEX_PASSKEY_*`-Attribute beim Speichern erhalten.
- Neue Passkeys haben den Signaturzähler 0 (Apple macht es bei seinen Passkeys nachweislich genauso). Importierte
  Passkeys mit Zähler > 0 müssen weiterzählen, sonst lehnen Websites sie ggf. ab. Das KeePassXC-Schema hat dafür kein
  Attribut – Lösung im Prototyp festlegen.
- Im Browser: Ein Skript in der Seite ersetzt `navigator.credentials.create/get` (so macht es Bitwarden). In
  sandboxed iframes und auf Nicht-HTTPS-Seiten (außer `localhost`) nicht eingreifen, sondern an die eingebaute
  WebAuthn-Funktion des Browsers weitergeben.

## Bitwarden-Import
- Der unverschlüsselte Bitwarden-JSON-Export enthält Passkeys (`fido2Credentials`) mit dem privaten Schlüssel im
  Klartext. Die Datei ist hochsensibel und muss nach dem Import gelöscht werden.
- KeePassXC importiert Passkeys aus diesem Export nicht – Ownwarden braucht einen eigenen Importer.
- Umzurechnen bzw. festzulegen: Credential-ID (GUID → 16 Byte oder base64url mit Präfix `b64.`), privater Schlüssel
  (base64 PKCS#8 → PEM), mehrere URIs pro Login, doppelte Namen eigener Felder (in KDBX nicht erlaubt), Favoriten
  (in KDBX kein eingebautes Merkmal), Eintragstypen ohne Gegenstück, Zählerstände.

## Plattform-Besonderheiten (Faktencheck 2026-10-14)

**Browser-Erweiterung (Vivaldi/Chrome):**
- Der Hintergrund-Prozess (Service Worker) wird nach 30 s ohne Aktivität beendet, ebenso wenn eine Antwort länger
  als 30 s dauert (relevant bei langsamem WebDAV). Entsperrter Schlüssel daher in `chrome.storage.session` (nur im
  Arbeitsspeicher, standardmäßig nicht für Content Scripts zugänglich).
- WebDAV-Zugriffe nur aus dem Service Worker bzw. Erweiterungsseiten, nie aus Content Scripts (für die gilt CORS
  der Webseite). Der vom Nutzer eingetragene WebDAV-Server muss als Host-Berechtigung erteilt sein (zur Laufzeit
  anfragen; `http` und `https` getrennt). Nachrichten-Handler prüfen, welche URLs sie abrufen dürfen.
- Verteilung auf einem privaten Windows-PC: nur „Entpackte Erweiterung laden“ (Entwicklermodus) oder Chrome Web Store
  (auch „nicht gelistet“; einmalige Registrierungsgebühr). Eine selbst gehostete `.crx` geht nur auf
  domänenverwalteten Windows-PCs. Vivaldi installiert Erweiterungen direkt aus dem Chrome Web Store.
- Automatisierte Tests: Das normale Chrome ignoriert seit Version 137 den Startparameter `--load-extension` –
  für Tests Chromium oder „Chrome for Testing“ verwenden.
- Clickjacking: Auf der DEF CON 33 (2025) wurden Passwortmanager-Erweiterungen (u. a. KeePassXC-Browser) über
  unsichtbare Overlays ausgetrickst. Autofill-Oberflächen direkt im DOM der Seite sind das anfällige Muster und
  brauchen Gegenmaßnahmen.

**Android:**
- Autofill Framework (ab Android 8) füllt native Apps. **In Chrome** nur, wenn der Nutzer in den Chrome-Einstellungen
  „Autofill using another service“ wählt; den Kompatibilitätsmodus unterstützt Chrome ab Version 137 nicht mehr.
- Die Web-Domain, die ein Browser meldet, nicht blind übernehmen: Browser über eine Freigabeliste mit
  Signaturprüfung verifizieren. Gespeicherte App-Zugangsdaten an die Signaturzertifikate der App binden, nicht nur
  an den Paketnamen. App↔Website-Zuordnung über Digital Asset Links.
- Passkeys über `CredentialProviderService` ab Android 14 (API 34); die Herkunft bei Browser-Anfragen über
  `CallingAppInfo.getOrigin(privilegedAllowlist)`. Liegt `minSdk` unter 34, braucht die App beide Wege.
- Biometrie: `BiometricPrompt` mit Keystore-Schlüssel (Klasse `BIOMETRIC_STRONG`). Der Schlüssel wird ungültig,
  sobald ein neuer Fingerabdruck/ein neues Gesicht registriert wird – dann Entsperren per Master-Passwort.

**WebDAV:**
- **MagentaCLOUD** läuft seit Ende 2021 auf Nextcloud. Adresse laut Telekom-Hilfe:
  `https://magentacloud.de/remote.php/webdav`, Benutzername = Telekom-Login (E-Mail-Adresse). Passwort: ein eigenes
  Passwort pro Gerät, das in der Web-Oberfläche erzeugt und nur einmal angezeigt wird. Jeder Client (Vivaldi, Chrome,
  Android) bekommt sein eigenes und muss einen Widerruf (`401`) sauber behandeln.
- **Nextcloud:** App-Passwörter verwenden (bei Zwei-Faktor-Anmeldung Pflicht).
- ETags sind undurchsichtige Versionskennungen: unverändert zurückschicken, nicht selbst berechnen, nicht zwischen
  Servern vergleichen.

## Sicherheitsregeln
- Domain-Abgleich mit der Public Suffix List (inkl. privater Abschnitt). Ein Treffer nur über die Basis-Domain
  braucht eine Bestätigung. Kein automatisches Ausfüllen in fremden iframes oder auf HTTP-Seiten ohne Bestätigung.
- Schutz gegen Clickjacking (siehe oben).
- Android: Browser-Freigabeliste mit Signaturprüfung, Bindung an App-Signaturen, Digital Asset Links (siehe oben).

## Annahmen, die im Prototyp geprüft werden müssen
- KeePassDX und Strongbox erhalten `Ownwarden.FieldTimes` und die Passkey-Attribute beim Speichern (ungeprüft).
  Für KeePassXC 2.7.6 ist das inzwischen durch Tests belegt (siehe „Bestätigte Fakten“).
- Strongbox auf dem iPad unterstützt KDBX-4.1-spezifische Felder (ungeprüft).
- MagentaCLOUD unterstützt bedingtes Schreiben mit `If-Match` (für Nextcloud im Quellcode belegt, für den
  Telekom-Betrieb nicht). Nutzer berichteten nach der Umstellung 2021 von unzuverlässigem WebDAV.
- MagentaCLOUD-WebDAV funktioniert laut Forenbeiträgen nicht mit einer externen E-Mail-Adresse als Telekom-Login.
- Ein abgebrochener Upload lässt die bisherige Datei auf dem Server unverändert.
- Der Bitwarden-JSON-Export enthält keine Anhänge (vermutlich; prüfen).

## Bestätigte Fakten (durch Tests gegen KeePassXC 2.7.6, Stand 2026-10-15)
- `Ownwarden.FieldTimes` übersteht Bearbeiten und Speichern in KeePassXC. KeePassXC kopiert CustomData aber NICHT in
  die Verlaufseinträge, die es beim Bearbeiten anlegt.
- KeePassXC setzt bei jedem Öffnen `_LAST_MODIFIED` in CustomData von Meta, Gruppen und Einträgen neu.
- KeePassXC normalisiert beim Speichern: Tags sortiert und mit `,` getrennt, Anhänge nach Namen sortiert und alle
  als geschützt markiert, leere Standardfelder werden angelegt, CR wird zu LF, Standard-`<AutoType>` wird ergänzt,
  IconID wird 0, wenn ein eigenes Icon gesetzt ist. Ownwarden wertet das nicht als Änderung.
- `keepassxc-cli db-create` (2.7.6) schreibt KDBX 3.1 mit AES-KDF; Ownwarden liest nur KDBX 4.x.

## Aktuelle Phase
Phase 0 – Prototyp des TypeScript-Kerns, gebaut in Etappen (jede mit kritischer Prüfung):
1. KDBX4-Container ✅  2. XML-Modell ✅  3. Feld-Merge ✅  4. WebDAV-Sync ⏳  5. Zusammenführen, CLI, Anleitung ⬜
Nur für Testdaten gedacht.

## Repo-Struktur
- `core/` – TypeScript-Kern (KDBX4, Feld-Merge, WebDAV-Sync), später von der Erweiterung genutzt
- `spec/` – sprachunabhängige Merge-Testfälle und Feld-Vektoren (auch für die spätere Kotlin-Implementierung)
- `tools/` – Hilfsmittel, z. B. ein WebDAV-Testserver
- geplant: `extension/` (Browser-Erweiterung, Manifest V3), `android/` (Kotlin), `docs/adr/`

## Roadmap
0. **Prototypen:**
   - KDBX4 lesen/schreiben in TypeScript gegen KeePassXC-Dateien; `Ownwarden.FieldTimes` übersteht das Speichern
     in KeePassXC?
   - WebDAV gegen Nextcloud und MagentaCLOUD: ETag, `If-Match`, `If-None-Match`, Abbruch beim Hochladen.
   - Manifest-V3-Erweiterung: Entsperren, Schlüssel in `chrome.storage.session`, Autofill auf einer Testseite.
   - Passkeys im Browser über das Ersetzen von `navigator.credentials` (Test z. B. gegen webauthn.io).
   - Android: Autofill- und Credential-Provider-Grundgerüst, Test in Chrome mit „Autofill using another service“.
1. TypeScript-Kern: KDBX4, Feld-Merge, WebDAV-Anbindung, Merge-Testfälle.
2. Browser-Erweiterung für Vivaldi/Chrome: Tresor, Autofill, Passkeys, Generator, Bitwarden-Import.
3. Android-App: Tresor, Autofill, Passkeys, Sync – besteht dieselben Testfälle aus `spec/`.
4. Umzug von Bitwarden.
5. iPad.

## Offene Punkte
- Verteilung der Erweiterung: Chrome Web Store (nicht gelistet) oder Entwicklermodus.
- Verteilung der Android-App: eigene signierte APK (Sideload) oder Store.
- KDBX-Version beim Schreiben (4.0 oder 4.1) und unterstützte Varianten beim Lesen (Twofish, AES-KDF).
- Build-Werkzeuge, Bibliotheken (Argon2, ChaCha20) und UI-Toolkits (im Prototyp festlegen).

## Definition of Done (Version 1)
- Auf Windows (Vivaldi und Chrome) und Android: Passwörter und Passkeys per Autofill nutzbar.
- Sync über Nextcloud und MagentaCLOUD ohne Datenverlust. Merge-Testfälle in `spec/` grün für: gleichzeitige
  Änderung verschiedener Felder, gleicher Zeitstempel, Feld entfernt gegen Feld geändert, Feld umbenannt, Löschen
  gegen Ändern, Papierkorb, Eintrag in andere Gruppe verschoben, Gruppe gelöscht, externe Änderung durch KeePassXC,
  Offline-Gerät, falsch gehende Geräteuhr, abgebrochener Upload, Vivaldi und Chrome schreiben gleichzeitig.
- Die Datei lässt sich jederzeit mit KeePassXC öffnen; Änderungen aus KeePassXC werden korrekt übernommen.
- Import des Bitwarden-JSON-Exports funktioniert, inklusive Passkeys.
- Der Code ist dokumentiert und für den Nutzer nachvollziehbar.

## Quellen des Faktenchecks (2026-10-14)
Von Recherche-Agenten abgerufen; mit * markierte habe ich selbst nachgeprüft.
- KeePassXC-Quellcode: [Merger.cpp](https://github.com/keepassxreboot/keepassxc/blob/develop/src/core/Merger.cpp)*,
  [EntryAttributes.cpp](https://github.com/keepassxreboot/keepassxc/blob/develop/src/core/EntryAttributes.cpp),
  [CustomData.cpp](https://github.com/keepassxreboot/keepassxc/blob/develop/src/core/CustomData.cpp),
  [KdbxXmlWriter.cpp](https://github.com/keepassxreboot/keepassxc/blob/develop/src/format/KdbxXmlWriter.cpp),
  [KeePass2.cpp](https://github.com/keepassxreboot/keepassxc/blob/develop/src/format/KeePass2.cpp)
- KeePass-Referenzcode (inoffizieller Spiegel):
  [KdbxFile.Write.cs](https://github.com/dlech/KeePass2.x/blob/master/KeePassLib/Serialization/KdbxFile.Write.cs)
- KeePassDX: [PasskeyEntryFields.kt](https://github.com/Kunzisoft/KeePassDX/blob/master/database/src/main/java/com/kunzisoft/keepass/model/PasskeyEntryFields.kt)
- Android: [Autofill services](https://developer.android.com/identity/autofill/autofill-services)*,
  [Credential provider](https://developer.android.com/identity/sign-in/credential-provider),
  [AutofillService](https://developer.android.com/reference/android/service/autofill/AutofillService),
  [Biometric auth](https://developer.android.com/identity/sign-in/biometric-auth)
- Chrome: [Service-Worker-Lebenszyklus](https://developer.chrome.com/docs/extensions/develop/concepts/service-workers/lifecycle),
  [Network requests](https://developer.chrome.com/docs/extensions/develop/concepts/network-requests),
  [Extensions deployment FAQ](https://www.chromium.org/developers/extensions-deployment-faq/)
- Bitwarden: [fido2-page-script.ts](https://github.com/bitwarden/clients/blob/main/apps/browser/src/autofill/fido2/content/fido2-page-script.ts),
  [fido2-authenticator.service.ts](https://github.com/bitwarden/clients/blob/main/libs/common/src/platform/services/fido2/fido2-authenticator.service.ts)
- WebAuthn: [W3C-Spezifikation (Quelltext)](https://github.com/w3c/webauthn/blob/main/index.bs),
  [Apple-Entwicklerforum zu signCount](https://developer.apple.com/forums/thread/712079)
- WebCrypto: [WICG Modern Algorithms](https://github.com/WICG/webcrypto-modern-algos)
- WebDAV: [Nextcloud WebDAV (Entwicklerdoku)](https://github.com/nextcloud/documentation/blob/master/developer_manual/client_apis/WebDAV/basic.rst),
  [SabreDAV Server.php](https://github.com/sabre-io/dav/blob/master/lib/DAV/Server.php),
  [Telekom-Hilfe MagentaCLOUD-Zugriff](https://cloud.telekom-dienste.de/hilfe/einrichten/zugriff-magentacloud)
