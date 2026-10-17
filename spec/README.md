# Ownwarden – Spezifikation des Feld-Merge

Dieser Ordner ist der **Vertrag zwischen den Implementierungen** (TypeScript für die
Browser-Erweiterung, Kotlin für Android, später Swift). Jede Implementierung muss

- alle Testfälle in `merge-cases/*.json` bestehen – **in beiden Richtungen** (local und
  remote vertauscht, das Ergebnis muss gleich sein), und
- für die Prüfwerte in `field-vectors.json` byte-genau dieselben kanonischen Werte,
  Fingerabdrücke und dasselbe `Ownwarden.FieldTimes`-JSON liefern.

Sonst hielte z. B. das Android-Gerät jedes Feld, das die Erweiterung versiegelt hat, für
„von einem fremden Programm geändert“, und beide Plattformen würden Gleichstände
verschieden entscheiden.

Die Referenzimplementierung steht in `core/src/merge/` (TypeScript), der Testläufer in
`core/src/merge/spec-cases.test.ts`. Die Regel selbst („neueste Änderung gewinnt – pro
Feld“) ist in `PROJECT-CONTEXT.md` begründet; hier steht, wie sie **genau** umgesetzt wird.

Alle Zeiten sind Millisekunden seit 1970-01-01 UTC. KDBX speichert Zeiten nur in ganzen
Sekunden – aus einer Datei gelesene Zeiten sind also Vielfache von 1000. Feld-Zeitstempel
in `Ownwarden.FieldTimes` sind millisekundengenau.

Zeiten, die diese Regeln aus einer anderen Zeit **ableiten** (`t + 1`, „nächste ganze
Sekunde“ = `(floor(t/1000) + 1) · 1000`, die monotone Uhr in Abschnitt 6), sind höchstens
**253402300799000** (Ende des KDBX-Zeitbereichs, Abschnitt 3): Dort bleiben sie stehen. Eine
spätere Zeit ließe sich nicht speichern, und in `Ownwarden.FieldTimes` machte sie die ganzen
FieldTimes des Eintrags ungültig. `t + 1` bedeutet also immer `min(t + 1, 253402300799000)`.

---

## 1. Felder

Ein Eintrag wird in Felder zerlegt. Jedes Feld hat einen Schlüssel (`FieldKey`):

| Schlüssel     | Inhalt                                                                  |
|---------------|-------------------------------------------------------------------------|
| `s:<Name>`    | ein `<String>`-Feld (Title, UserName, Password, URL, Notes, eigene Felder) außer Passkey-Attributen |
| `passkey`     | alle Attribute, deren Name mit `KPEX_PASSKEY_` oder `KPXC_PASSKEY_` beginnt, als **eine** Einheit |
| `a:<Name>`    | ein Anhang                                                              |
| `cd:<Key>`    | ein CustomData-Eintrag des Eintrags, außer `Ownwarden.FieldTimes` und `_LAST_MODIFIED` |
| `tags`        | die Tags                                                                |
| `icon`        | IconID und CustomIconUUID                                               |
| `colors`      | Vorder- und Hintergrundfarbe                                            |
| `overrideUrl` | OverrideURL                                                             |
| `expiry`      | Ablauf (Expires + ExpiryTime)                                           |
| `misc`        | QualityCheck, PreviousParentGroup und alle unbekannten XML-Elemente (z. B. `<AutoType>`) |
| `parent`      | die Gruppe, in der der Eintrag liegt (Position im Baum; nur bei aktuellen Einträgen, nicht im Verlauf) |

Ein Feld ist **vorhanden** oder **nicht vorhanden**. Nicht vorhanden ist es, wenn es nicht
existiert oder seinen Standardwert hat:

| Feld          | vorhanden, wenn …                                                         |
|---------------|----------------------------------------------------------------------------|
| `s:<Name>`    | das Feld existiert und **kein leeres Standardfeld** ist (leeres Title/UserName/Password/URL/Notes zählt als nicht vorhanden; ein leeres *eigenes* Feld ist vorhanden) |
| `passkey`     | mindestens ein Passkey-Attribut existiert                                 |
| `a:<Name>`    | der Anhang existiert                                                       |
| `cd:<Key>`    | der Eintrag existiert                                                      |
| `tags`        | nach der Vereinheitlichung (siehe unten) mindestens ein Tag übrig bleibt   |
| `icon`        | ein eigenes Icon gesetzt ist oder IconID ≠ 0                               |
| `colors`      | Vorder- oder Hintergrundfarbe ≠ ""                                         |
| `overrideUrl` | OverrideURL ≠ ""                                                           |
| `expiry`      | Expires = True                                                             |
| `misc`        | QualityCheck = False, oder PreviousParentGroup gesetzt, oder mindestens ein *bedeutsames* unbekanntes Element (siehe unten) |
| `parent`      | immer (bei aktuellen Einträgen)                                            |

Ein Feld zu entfernen ist also dasselbe wie es auf den Standardwert zu setzen.
Umbenennen = altes Feld entfernen + neues anlegen.

## 2. Kanonischer und exakter Wert

Zwei Fassungen eines Felds sind **gleich**, wenn ihre kanonischen Werte (Bytes) gleich
sind. Der kanonische Wert gleicht Umformungen aus, die KeePassXC 2.7.6 beim Speichern
vornimmt, ohne dass der Nutzer etwas geändert hat (sonst sähe jedes Öffnen und Speichern in
KeePassXC wie eine Änderung aus – siehe `core/src/merge/merge.interop.test.ts`).

Der **exakte** Wert enthält die Rohdaten. Er wird nur als letzte Gleichstand-Regel
gebraucht (Abschnitt 5.1), damit das Ergebnis auch dann nicht von der Rolle der Seiten
abhängt, wenn sich zwei Fassungen nur in solchen Kleinigkeiten unterscheiden.

### 2.1 Kodierung `encodeParts`

Beide Werte sind Listen von **Teilen**, kodiert so:

```
encodeParts([t1, t2, …]) = für jedes Teil: Länge (uint32, Big Endian) + Bytes des Teils
```

- Text → UTF-8 (einzelne UTF-16-Surrogate → U+FFFD; kommen in XML nicht vor)
- Bytes (Anhänge) → unverändert
- Zahl → Dezimaltext ohne führende Nullen (`"12"`, negativ mit `-`)
- Wahrheitswert → `"1"` oder `"0"`
- Liste in einer Liste → `encodeParts(liste)`, als ein Teil

Beispiel: `encodeParts(["s", "Mail", "0"])` = `00000001 73 00000004 4d61696c 00000001 30`.

Bytes werden **lexikografisch als vorzeichenlose Bytes** verglichen; ist eine Folge Präfix
der anderen, ist sie kleiner. Texte werden über ihre UTF-8-Bytes verglichen (= Reihenfolge
der Unicode-Codepunkte, nicht UTF-16!). Das gilt für jede Sortierung in dieser Spezifikation.

### 2.2 Vereinheitlichungen

- `lf(x)`: `"\r\n"` und einzelnes `"\r"` werden zu `"\n"`.
- `text(v)`: bei einem **geschützten** Wert ein einzelnes U+FEFF am Anfang entfernen
  (KeePassXC verliert es beim Laden), dann `lf`.
- `tags(liste)`: jedes Tag ohne Leerraum am Rand, leere und doppelte weg, sortiert.
  „Leerraum“ sind **genau** diese Zeichen (nicht das `trim()` der jeweiligen Sprache – Kotlins
  `trim()` entfernt z. B. U+FEFF nicht): U+0009–U+000D, U+0020, U+00A0, U+1680,
  U+2000–U+200A, U+2028, U+2029, U+202F, U+205F, U+3000, U+FEFF.
- *Bedeutsame* unbekannte Elemente: alle außer genau dem Standard-AutoType, das KeePassXC
  jedem Eintrag ohne AutoType hinzufügt:
  `<AutoType><Enabled>True</Enabled><DataTransferObfuscation>0</DataTransferObfuscation><DefaultSequence/></AutoType>`
  (auch ohne `<DefaultSequence/>` oder mit `<DefaultSequence></DefaultSequence>`).
- Unbekannte Elemente stehen im Modell als kompakter XML-Text (so legt sie der XML-Leser ab,
  `core/src/kdbx/xml-dom.ts`, `serializeElement`): ohne Einrückung; Leerraum zwischen
  Kind-Elementen verworfen, reiner Textinhalt unverändert; Attribute in Originalreihenfolge
  als `name="wert"`; leeres Element als `<Name/>`; in Text `& < > "` als `&amp; &lt; &gt; &quot;`
  und `"\r"` als `&#13;`; in Attributen zusätzlich Tab/LF als `&#9;`/`&#10;`; in XML
  ungültige Zeichen als `&#n;` (n = UTF-16-Einheit dezimal).

### 2.3 Werte je Feld

`p` = Schutz-Flag als `"1"`/`"0"`. `uuid` = Base64 der 16 Byte, wie in der KDBX-XML (mit `==`).

| Feld          | kanonisch                                                       | exakt                                                          |
|---------------|-----------------------------------------------------------------|----------------------------------------------------------------|
| `s:<Name>`    | `["s", text(v), p]`                                             | `["s", v, p]`                                                  |
| `passkey`     | `["passkey", n1, text(v1), p1, n2, text(v2), p2, …]`, Attribute nach Namen sortiert | wie kanonisch, aber mit Rohwerten `v` |
| `a:<Name>`    | `["a", bytes]` (Schutz-Flag zählt **nicht** – KeePassXC setzt es immer) | `["a", bytes, p]`                                       |
| `cd:<Key>`    | `["cd", lf(wert)]`                                              | `["cd", wert, lastModified oder ""]`                           |
| `tags`        | `["tags", …tags(liste)]`                                        | `["tags", …liste roh]`                                         |
| `icon`        | eigenes Icon: `["icon", "c", uuid]`, sonst `["icon", "i", iconId]` (mit eigenem Icon zählt die IconID nicht – KeePassXC setzt sie dann auf 0) | `["icon", iconId, uuid oder ""]` |
| `colors`      | `["colors", vordergrund, hintergrund]`                          | gleich                                                         |
| `overrideUrl` | `["overrideUrl", url]`                                          | gleich                                                         |
| `expiry`      | `["expiry", floor(expiryTime / 1000)]` (ganze Sekunden)         | `["expiry", expires, expiryTime]`                              |
| `misc`        | `["misc", QualityCheck = False ? "0" : "1", previousParentGroup oder "", …bedeutsame unbekannte Elemente]` (fehlendes QualityCheck = True) | `["misc", "u"/"1"/"0", previousParentGroup oder "", …alle unbekannten Elemente]` |
| `parent`      | `["parent", uuid der Gruppe]`                                   | gleich                                                         |

Der exakte Wert eines **nicht vorhandenen** Felds ist für Eigenschafts-Felder (`tags`,
`icon`, `colors`, `overrideUrl`, `expiry`, `misc`) die exakte Kodierung des Rohwerts, für
alle anderen die leere Bytefolge.

## 3. Fingerabdruck und `Ownwarden.FieldTimes`

**Fingerabdruck** = Base64url ohne `=` (RFC 4648 §5) der ersten 12 Byte von SHA-256 über
den kanonischen Wert (16 Zeichen).

Ownwarden speichert pro Eintrag **einen** CustomData-Eintrag `Ownwarden.FieldTimes` mit
kompaktem JSON (keine Leerzeichen; Feldschlüssel nach UTF-8-Bytes sortiert; Zahlen als
ganze Dezimalzahlen; Texte maskiert wie `JSON.stringify` in JavaScript: `\"`, `\\`, `\b`,
`\f`, `\n`, `\r`, `\t`, übrige Zeichen unter U+0020 als `\u00xx` mit kleinen Hex-Ziffern,
einzelne Surrogate als `\udxxx`, alles andere – auch `/`, U+007F, U+2028 und Nicht-ASCII –
unverändert):

```json
{"v":1,"w":1700000003000,"f":{"parent":{"t":1700000000000,"h":"ZKWE5L8inDQMXCpy"},"s:Alt":{"t":1700000002000,"d":1}}}
```

- `v` – Formatversion, immer `1`.
- `w` – `times.lastModification` des Eintrags beim Versiegeln.
- `f` – pro Feld `{"t": Zeit, "h": Fingerabdruck}` (vorhanden) oder `{"t": Zeit, "d": 1}`
  (Lösch-Marker: Feld wurde zur Zeit t entfernt).

Die `LastModificationTime` einzelner CustomData-Einträge wird **nicht** benutzt (KeePassXC
verwirft sie). Verlaufseinträge haben keine FieldTimes.

**Lesen:** Ungültig (= wie „keine FieldTimes“) ist der Wert, wenn er kein JSON-Objekt ist,
`v` ≠ 1, `w` keine gültige Zeit, `f` kein Objekt, oder ein Feld-Eintrag kein Objekt ist, kein
gültiges `t` hat oder weder `"d":1` noch ein Text-`h`. **Gültige Zeit** = ganze Zahl im
KDBX-Zeitbereich (Jahr 1 bis 9999): −62135596800000 ≤ t ≤ 253402300799000. (Eine unsinnige
Zeit wie „Jahr 33658“ gewönne sonst jeden Vergleich, und das Ergebnis ließe sich nicht mehr
speichern.) Die Prüfung gilt für jeden Feld-Eintrag in `f`. Danach übersprungen (ohne
Wirkung) werden genau die Feldschlüssel, die keine Felder sind:

- Schlüssel, deren Art das Feld-Modell nicht kennt – alles außer `s:…`, `a:…`, `cd:…`,
  `passkey`, `parent`, `tags`, `icon`, `colors`, `overrideUrl`, `expiry`, `misc`
  (z. B. `x:A`, `Title`);
- `s:` mit einem Passkey-Attribut als Namen (`s:KPEX_PASSKEY_…`, `s:KPXC_PASSKEY_…`; sie
  gehören zu `passkey`);
- `cd:Ownwarden.FieldTimes` und `cd:_LAST_MODIFIED`.

`s:`, `a:` und `cd:` mit **leerem** Namen sind gewöhnliche Schlüssel: Ein Feld, ein Anhang
oder ein CustomData-Eintrag mit leerem Namen kann in einer Datei vorkommen und ist dann ein
ganz normales Feld.

**Versiegeln** (nach jeder Änderung durch Ownwarden und nach jedem Zusammenführen): für
jedes vorhandene Feld `{"t", "h"}` mit frischem Fingerabdruck, für jedes bekannte entfernte
Feld `{"t", "d":1}`; `w` = `times.lastModification`. Lösch-Marker werden nie gelöscht
(sonst brächte ein Gerät, das lange offline war, das Feld zurück). Jedes geschriebene `t` und
`w` muss eine gültige Zeit sein; sonst ist das ein Programmfehler und es wird nicht versiegelt
(die Referenz wirft einen Fehler) – FieldTimes, die beim nächsten Lesen ungültig wären,
nähmen dem Eintrag still alle Lösch-Marker.

## 4. Wirksame Feld-Zeitstempel

Für jeden Eintrag (mit seiner Gruppe) ergibt sich pro Feld ein Zeitpunkt `t` und ob das
Feld vorhanden ist. Basiszeit = `times.lastModification`, für `parent` `times.locationChanged`,
jeweils **auf ganze Sekunden abgerundet** (`floor(x/1000)·1000`; PROJECT-CONTEXT: KDBX-Zeiten
werden beim Vergleich mit Feld-Zeitstempeln auf Sekunden abgerundet). Sonst bekäme dasselbe
Feld im Speicher (ms) eine andere Zeit als nach dem Laden aus der Datei, und zwei Geräte
entschieden denselben Abgleich verschieden.

**Mit gültigen FieldTimes:**

| Lage                                                         | Ergebnis                                         |
|--------------------------------------------------------------|--------------------------------------------------|
| Feld vorhanden, Eintrag in `f` vorhanden, Fingerabdruck passt | `t` aus `f`                                     |
| Feld vorhanden, Fingerabdruck passt nicht oder `f` hat einen Lösch-Marker | **extern geändert**: `t = max(Basiszeit, t_f + 1)` |
| Feld vorhanden, `f` kennt es nicht                           | **extern angelegt**: `t = Basiszeit`             |
| Feld fehlt, `f` hat einen Lösch-Marker                       | entfernt zur Zeit des Markers                    |
| Feld fehlt, `f` hat es als vorhanden                         | **extern entfernt**: Lösch-Marker bei `max(Basiszeit, t_f + 1)` |

Der Eintrag gilt (nur für den Bericht) als extern geändert, wenn eine der fett markierten
Lagen auftritt oder `floor(lastModification/1000) > floor(w/1000)`.

**Ohne (gültige) FieldTimes** – der Eintrag wurde nie von Ownwarden geschrieben, z. B. in
KeePassXC angelegt: Grundregel `t = Basiszeit` für jedes vorhandene Feld. Verfeinerung über
den Verlauf (KeePassXC legt bei jeder Änderung die vorherige Fassung dorthin): Fassungen
`V0 … Vn-1` = Verlauf (älteste zuerst), `Vn` = der Eintrag; `L(i)` = `min(Vi.lastModification, Vn.lastModification)`,
auf ganze Sekunden abgerundet.

- Vorhandenes Feld (außer `parent`): `j` = kleinster Index, ab dem `Vj … Vn` alle denselben
  kanonischen Wert haben → `t = L(j)` (ohne Verlauf: `L(n)`).
- Feld, das in irgendeiner Fassung des Verlaufs vorhanden war und jetzt fehlt: `j` =
  kleinster Index, ab dem es in `Vj … Vn` fehlt → Lösch-Marker bei `L(j)`.
- `parent`: `t = locationChanged`. Keine sonstigen Lösch-Marker.

So überschreibt z. B. eine Benutzernamen-Änderung in KeePassXC nicht das Passwort, das
Ownwarden auf einem anderen Gerät (früher) geändert hat (Testfall 14).

Haben **beide** Seiten eines Zusammenführens keine gültigen FieldTimes, kommen beim
Zusammenführen noch Lösch-Marker der neueren Seite hinzu (Abschnitt 5.1).

## 5. Zusammenführen (`mergeVaults(local, remote, now)`)

Reine Funktion: Die Eingaben werden nicht verändert. Inhaltlich hängt das Ergebnis nicht
davon ab, welche Seite local ist (nur die Reihenfolge von Geschwistern, die von local
übernommenen Meta-Angaben und KDBX-Einstellungen (5.5) und das Feld `winner` im Bericht).
Voraussetzung: keine doppelten UUIDs innerhalb einer Seite (5.2). Ein Client gleicht nicht
mit `mergeVaults(local, server)` ab, sondern übernimmt vorher die Einstellungen der
Server-Datei (5.7).

### 5.1 Einträge

Einträge werden über den **ganzen Baum** per UUID zugeordnet (sie dürfen auf beiden Seiten in
verschiedenen Gruppen liegen).

- **Nur auf einer Seite** → unverändert übernehmen (danach Löschen gegen Ändern, 5.3).
- **Auf beiden Seiten gleich** (alles gleich, auch Verlauf und Gruppe; `_LAST_MODIFIED`
  zählt nicht) → unverändert übernehmen; unterscheidet sich `_LAST_MODIFIED`, fällt es weg.
- **Sonst** pro Feld (alle Schlüssel mit Wert oder Lösch-Marker auf einer der Seiten, dazu
  immer `tags`, `icon`, `colors`, `overrideUrl`, `expiry`, `misc`, `parent`): Es gewinnt
  1. der größere wirksame Zeitstempel `t` (kennt eine Seite das Feld gar nicht: −∞),
  2. bei Gleichstand: vorhanden vor nicht vorhanden,
  3. dann der größere kanonische Wert,
  4. dann der größere exakte Wert;
  sind alle gleich, sind die Fassungen gleich (local wird genommen).

  **Beide Seiten ohne gültige FieldTimes** (Abschnitt 4, z. B. in KeePassXC angelegt und von
  Ownwarden nie geändert) mit verschiedener `lastModification` **in ganzen Sekunden**: Die
  neuere Seite ist maßgeblich dafür, welche Felder **fehlen**. Für jedes Feld, das auf der
  älteren Seite vorhanden ist und auf der neueren nicht, bekommt die neuere Seite VOR der
  Entscheidung oben einen Lösch-Marker zu ihrer Basiszeit (`floor(lastModification/1000)·1000`)
  – auch wenn ihr Verlauf einen früheren Lösch-Marker ergab. Die ältere Seite kann das Feld
  nicht über Ownwarden angelegt haben (dann wäre sie versiegelt); ohne diese Regel hätte ein
  Feld, das in KeePassXC ohne Verlaufseintrag entfernt wurde (HistoryMaxItems = 0, Verlauf
  über HistoryMaxSize oder gelöscht), auf der neueren Seite gar keine Zeit, und jede ältere
  Kopie brächte es zurück (Testfall 32). Ein solcher Marker zählt im Bericht als „kennt das
  Feld“. In derselben Sekunde gibt es keine maßgebliche Seite.

  Der Gewinner liefert den Rohwert (oder das Fehlen) des Felds, `parent` die Gruppe.
  Fehlende Standardfelder werden leer angelegt (Password geschützt), wie bei KeePass.

  Zeiten: `creation` = min, `lastModification` = max(beide Seiten, alle Gewinner-`t`),
  `lastAccess` = max, `usageCount` = max, `locationChanged` = `t` des gewinnenden `parent`,
  Ablauf aus dem Gewinner von `expiry`. Danach neu versiegeln (Abschnitt 3) mit den
  Gewinner-Zeitstempeln (Felder, die keine Seite kannte, bekommen keinen Eintrag).

  **Verlauf:** beide Verläufe + die aktuelle Fassung jeder Seite, deren *Inhalt* vom Ergebnis
  abweicht (Inhalt = Fingerabdruck über alle vorhandenen Felder außer `parent`: SHA-256 über
  `encodeParts([key1, kanonisch1, key2, kanonisch2, …])`, Schlüssel sortiert, erste 12 Byte,
  Base64url). Diese Fassungen ohne eigenen Verlauf, ohne `Ownwarden.FieldTimes` und ohne
  `_LAST_MODIFIED`. Doppelte (gleiche `lastModification` **in ganzen Sekunden** und gleicher
  Inhalt **ohne** die `cd:`-Felder – KeePassXC übernimmt CustomData nicht in seine
  Verlaufseinträge, dieselbe Fassung kann also einmal mit und einmal ohne ankommen; und
  dieselbe Fassung kommt oft einmal aus dem Speicher (ms) und einmal aus der Datei (s)) nur
  einmal. Welche bleibt, ist eine **feste Reihenfolge über alle Rohdaten** – unabhängig von der
  Rolle der Seiten und davon, ob eine Fassung aus dem Speicher (ms) oder aus der Datei (s)
  kommt. Sonst behielte jedes Gerät seine eigene Fassung und lüde sie bei jedem Abgleich
  wieder hoch (Testfall 33). Behalten wird die größere nach
  1. dem Rohdaten-Fingerabdruck **über die auf ganze Sekunden abgerundeten Zeiten** (auch
     Ablaufzeit und `LastModificationTime` von CustomData), als Text verglichen;
  2. dann der vollständigen Kodierung über die abgerundeten Zeiten;
  3. dann der vollständigen Kodierung über die genauen Zeiten.

  Erst alles, was nach Speichern und Laden noch zu sehen ist (ganze Sekunden), dann die
  Millisekunden: Sonst entschiede ein Gerät, das die Fassung im Speicher hat, anders als eines
  mit derselben Fassung aus der Datei.

  Rohdaten-Fingerabdruck = Fingerabdruck wie in Abschnitt 3 über
  `encodeParts([key1, exakt1, key2, exakt2, …, creation, lastModification, lastAccess, expiry, usageCount, locationChanged, expires])`
  mit allen **vorhandenen** Feldern nach Schlüssel sortiert. Er sieht nicht alles – z. B. nicht
  das Standard-`<AutoType>` (es macht `misc` nicht vorhanden), das KeePassXC 2.7.6 beim
  Speichern auch in jeden Verlaufseintrag schreibt. Deshalb danach die **vollständige
  Kodierung** aller Rohdaten der Fassung (Bytes, verglichen wie in 2.1):

  ```
  encodeParts([
    uuid, iconId, customIconUuid oder "", Vordergrundfarbe, Hintergrundfarbe, OverrideURL,
    [Tag1, Tag2, …],                       Tags roh, in ihrer Reihenfolge
    [creation, lastModification, lastAccess, expiry, usageCount, locationChanged, expires],
    [Name1, Wert1, p1, Name2, …],          ALLE <String>-Felder roh (auch leere Standardfelder
                                           und Passkey-Attribute), nach Namen sortiert
    [Name1, Bytes1, p1, Name2, …],         alle Anhänge, in ihrer Reihenfolge
    [Schlüssel1, Wert1, lastModified1 oder "", …]
                                           ALLE CustomData-Einträge (auch Ownwarden.FieldTimes
                                           und _LAST_MODIFIED), nach Schlüssel sortiert
    QualityCheck ("u" = fehlt, "1", "0"), previousParentGroup oder "",
    [Element1, Element2, …]                alle unbekannten Elemente roh, in ihrer Reihenfolge
  ])
  ```

  Zahlen als Dezimaltext, `expires` und `p` als `"1"`/`"0"`, `[…]` = verschachtelte Liste (ein
  Teil). Der eigene Verlauf einer Fassung zählt nicht (im Verlauf fällt er weg). Sind alle drei
  Werte gleich, unterscheiden sich die Fassungen höchstens in der Reihenfolge ihrer Felder oder
  ihres CustomData – das zählt nirgends; behalten wird dann eine beliebige. Sortiert nach
  `lastModification` in ganzen Sekunden, dann dem Inhalts-Fingerabdruck ohne `cd:` (danach
  eindeutig). Gekürzt nach
  den Grenzen von **local**: erst `HistoryMaxItems` (die neuesten bleiben), dann
  `HistoryMaxSize`: von der neuesten Fassung rückwärts die Größen addieren; ab der ersten
  Fassung, mit der die Summe die Grenze überschreitet, fallen sie und alle älteren weg.
  Größe einer Fassung ≈ Länge aller Feldnamen und -werte und CustomData-Schlüssel/-Werte (in
  UTF-16-Einheiten) + Namen und Bytes aller Anhänge. −1 = unbegrenzt.

  **Feldkonflikt (Bericht):** jedes Feld, das beide Seiten kennen (Wert oder Lösch-Marker)
  und dessen Inhalt (vorhanden? + kanonischer Wert) sich unterscheidet; `tieBreak` = gleiche
  Zeitstempel.

### 5.2 Doppelte UUIDs

**Voraussetzung für `mergeVaults`:** Innerhalb EINER Seite sind die UUIDs aller Gruppen (mit
Wurzel) und aller Einträge (ohne Verlaufseinträge) verschieden – Gruppen und Einträge teilen
sich einen Namensraum. Sonst ist das ein Programmfehler, und `mergeVaults` bricht mit einem
Fehler ab (die Referenz wirft), statt die Vorkommen still zu einem Objekt zusammenzulegen –
dabei ginge eines samt Passwort verloren. Dass die Voraussetzung gilt, stellt der KDBX-Leser
sicher:

**Leseregel (verbindlich für jede Implementierung):** Kommen in einer Datei UUIDs von Gruppen
oder Einträgen mehrfach vor (in der KeePass-Welt gibt es solche Dateien; KeePass 2.x bietet
dafür eigens „doppelte UUIDs reparieren“ an), bekommt beim Lesen jedes SPÄTERE Vorkommen eine
neue UUID. Sie wird aus der alten **abgeleitet**, nicht gewürfelt: Jedes Gerät, das dieselbe
Datei liest, kommt auf dieselbe neue UUID und sieht beim Abgleich dasselbe Objekt; beim
nächsten Speichern steht sie in der Datei, danach ist die Datei repariert. Referenz:
`core/src/kdbx/duplicate-uuids.ts`.

1. **Vergeben** sind alle UUIDs der Datei: jede `<UUID>` einer Gruppe, eines Eintrags und
   eines Verlaufseintrags, jede UUID in `<DeletedObjects>`, dazu die Null-UUID
   (`AAAAAAAAAAAAAAAAAAAAAA==`).
2. Gruppen und Einträge (OHNE Verlaufseinträge) werden in **Dokumentreihenfolge** durchlaufen:
   Reihenfolge der öffnenden Tags `<Group>`/`<Entry>`; eine Gruppe kommt also vor ihrem
   Inhalt, die Wurzelgruppe zuerst. Gruppen und Einträge teilen sich EINEN Namensraum (wie
   bei KeePass; auch Lösch-Vermerke unterscheiden nicht zwischen Gruppe und Eintrag).
3. Das erste Vorkommen einer UUID behält sie. Für jedes weitere Vorkommen der UUID `u`:
   `k` = Zähler für `u` (beginnt bei 0). Wiederhole `k := k + 1`,
   `Kandidat` = erste 16 Byte von SHA-256( UTF-8(`"Ownwarden-Duplicate"`) ‖ die 16 Byte von
   `u` ‖ `k` als uint32 **Little Endian** ), solange der Kandidat schon vergeben ist. Der
   Kandidat wird die neue UUID und gilt ab dann als vergeben; der Zähler von `u` bleibt für
   das nächste Vorkommen von `u` stehen.
4. Die Verlaufseinträge eines umbenannten Eintrags bekommen dieselbe neue UUID (sie gehören zu
   ihm). Verlaufseinträge zählen selbst NIE als Vorkommen – sie tragen rechtmäßig die UUID
   ihres Eintrags.

Verweise auf die alte UUID (RecycleBinUUID, PreviousParentGroup, `{REF:…}`) werden nicht
umgeschrieben; sie meinen weiterhin das erste Vorkommen. Beispiel: `u` =
`l8ruJYQAj5WS5uV32csPAQ==` (Name `"doppelt"` nach 7.1) → zweites Vorkommen
`v34trW/2XP1goJfcx5kIJg==` (`k` = 1), drittes `5PpYLyDtzicRvVNYd2ZAug==` (`k` = 2), sofern
nicht schon vergeben.

**Verschiedene Wurzeln:** Haben beide Seiten verschiedene Wurzel-UUIDs, gelten beide Wurzeln
als dieselbe Gruppe; ihre UUID im Ergebnis ist die kleinere (Base64-Text, UTF-8-Bytes). Eine
Untergruppe der einen Seite mit dieser UUID (der Wurzel-UUID der anderen Seite) wird Teil der
Wurzel.

### 5.3 Löschen gegen Ändern

Lösch-Vermerke (DeletedObjects) beider Seiten werden vereinigt (pro UUID die späteste Zeit).
Hat ein Eintrag (nach 5.1) einen Lösch-Vermerk mit Zeit `D`: Änderungszeit des Eintrags =
max(alle wirksamen Feld-Zeitstempel inkl. Lösch-Marker, `lastModification`,
`locationChanged`). Verglichen wird in **ganzen Sekunden** (`floor(x/1000)`): Ist die
Änderung **echt neuer** als die Löschung, bleibt der Eintrag und sein Lösch-Vermerk
verschwindet („wiederbelebt“); sonst (auch bei Gleichstand) ist er gelöscht.
In den Papierkorb verschieben ist **keine** Löschung, nur eine Änderung von `parent`.

### 5.4 Gruppen

Gruppen werden per UUID zugeordnet. Gruppen haben keine millisekundengenauen
Feld-Zeitstempel; **alle Gruppen-Zeiten werden in ganzen Sekunden verglichen** (`floor(x/1000)`).
Sonst hielte beim Abgleich jedes Gerät seine eigene Fassung im Speicher (ms) für neuer als
dieselbe Änderungssekunde aus der Datei, und zwei Geräte schrieben sich gegenseitig ihre Fassung
zurück. Zwei Entscheidungen:

- **Eigenschaften** (Name, Notizen, Icon, Tags, CustomData, Ablauf, unbekannte Elemente,
  PreviousParentGroup) als Einheit: größere `times.lastModification` (ganze Sekunden) gewinnt;
  Gleichstand: größerer kanonischer, dann größerer exakter Wert.
  kanonisch = `encodeParts(["group", name, lf(notizen), icon, tags(liste), customData, unbekannte, previousParentGroup oder "", Ablauf])`
  mit icon = `["c", uuid]` bzw. `["i", iconId]`; customData = Liste `[key1, lf(wert1), …]`
  nach Schlüssel sortiert, ohne `Ownwarden.FieldTimes`/`_LAST_MODIFIED`; unbekannte = Liste
  der Elemente (roh); Ablauf = `floor(expiry/1000)` falls Expires, sonst `""`.
  exakt = `encodeParts(["group", name, notizen, [iconId, uuid oder ""], tags roh, [key, wert, lastModified oder "", …], unbekannte, previousParentGroup oder "", [expires, expiry]])`.
- **Elterngruppe**: größere `times.locationChanged` (ganze Sekunden) gewinnt; Gleichstand:
  größere Eltern-UUID (Base64-Text, UTF-8-Bytes). Die Wurzel hat keine.

Zeiten: `creation` min, `lastModification`/`lastAccess`/`usageCount` max, `locationChanged`
vom Gewinner der Elterngruppe (haben beide Seiten dieselbe Elterngruppe: das Maximum), Ablauf vom
Gewinner der Eigenschaften.

**Zyklen** (local schiebt A unter B, remote B unter A): In jedem Kreis kommt die Gruppe mit
der kleinsten `locationChanged` (ganze Sekunden; Gleichstand: kleinere UUID als Base64-Text)
direkt unter die Wurzel.

**Gelöschte Gruppe** (Lösch-Vermerk `D`): Sie bleibt, wenn ihre eigene Änderung
(max(`lastModification`, `locationChanged`)) oder die Änderung irgendeines **bestehen
bleibenden** Nachfahren (Einträge: wie in 5.3; Gruppen: eigene Änderung) in ganzen Sekunden
echt neuer ist als `D`. Sonst ist sie gelöscht. Bleibt sie, verschwindet ihr Lösch-Vermerk.

**Waisen:** Bestehende Einträge/Gruppen, deren Elterngruppe es nicht mehr gibt, kommen in die
**Wiederherstellungsgruppe**: feste UUID `T3dud2FyZGVuUmVjb3Zlcg==` (die 16 ASCII-Bytes
`OwnwardenRecover`), Name `Wiederhergestellt (Ownwarden)`, Icon 48, direkt unter der Wurzel.
Gibt es sie schon, wird sie benutzt; sonst wird sie angelegt mit allen Zeiten =
max(`now`, (ganze Sekunde ihres Lösch-Vermerks + 1) · 1000) und ihr Lösch-Vermerk entfällt.

**Verschiebung durch den Merge** (Zyklus, Waise): bei Gruppen neue Verschiebezeit =
max(`now`, (ganze Sekunde der alten Verschiebezeit + 1) · 1000); bei Einträgen
max(`now`, alte Zeit von `parent` + 1), sie bekommen `locationChanged` = `lastModification` =
max(alt, neu), `parent` = neue Zeit, neu versiegelt.
So trifft ein späterer Abgleich mit einer der Eingaben dieselbe Entscheidung.

### 5.5 Lösch-Vermerke, Meta, Reihenfolge

- **Lösch-Vermerke** im Ergebnis: alle vereinigten außer denen, deren UUID im Ergebnis
  vorhanden ist (Eintrag, Gruppe, behaltenes Icon). Vermerke für unbekannte UUIDs bleiben.
- **Meta** (alle Zeiten in **ganzen Sekunden** verglichen, wie bei Gruppen): Datenbankname
  nach `DatabaseNameChanged` (Gleichstand: der größere Name, UTF-8-Bytes), Papierkorb (an/aus
  + UUID als Einheit) nach `RecycleBinChanged` (Gleichstand: das größere
  `encodeParts([an ? "1" : "0", RecycleBinUUID])`, die UUID als Base64-**Text** wie in der XML –
  auch bei ausgeschaltetem Papierkorb –, Bytes verglichen wie in 2.1; also zuerst an vor aus,
  dann die UUID als Text, nicht ihre 16 Byte – Testfall 34). Bei gleichem Wert auf beiden
  Seiten bekommt das Ergebnis jeweils die spätere der beiden Zeiten. Eigene Icons:
  Vereinigung nach UUID, bei beiden Seiten gewinnt die neuere `LastModificationTime` (fehlend = −∞; Gleichstand: größeres
  `encodeParts([daten, name oder "", lastModified oder ""])`); ein Icon mit neuerem
  Lösch-Vermerk fällt weg, außer ein Eintrag (auch im Verlauf) oder eine Gruppe benutzt es.
  CustomData: Vereinigung, bei gleichem Schlüssel gewinnt die neuere `LastModificationTime`
  (fehlend = −∞), bei Gleichstand – in KDBX 4.0 der Normalfall – das größere
  `encodeParts([wert, lastModified oder ""])` (nicht local: sonst behielte jedes Gerät seinen
  Wert und schriebe ihn immer wieder zurück). Verlaufsgrenzen, unbekannte Elemente und
  KDBX-Einstellungen von local (KDBX-Nebenversion = Maximum), unbekannte Elemente von
  `<Root>` ebenfalls von local – beim Abgleich setzt der Client hier vorher die Werte der
  Server-Datei ein (5.7). Generator `Ownwarden`.
- **Reihenfolge der Geschwister:** zuerst wie in local, dann die übrigen wie in remote, dann
  der Rest (z. B. Waisen) nach Position in local, dann in remote, dann UUID.

### 5.6 Bericht

| Angabe                   | Bedeutung                                                              |
|--------------------------|------------------------------------------------------------------------|
| `entriesAddedFromRemote` | Einträge im Ergebnis, die local nicht hatte (ohne wiederbelebte)       |
| `entriesUpdated`         | Einträge aus local, deren Inhalt oder Gruppe sich geändert hat         |
| `entriesDeleted`         | Einträge aus local oder remote, die nicht im Ergebnis sind             |
| `entriesResurrected`     | Einträge im Ergebnis, die einen Lösch-Vermerk hatten                   |
| `groupsChanged`          | Gruppen (inkl. Wurzel), die gegenüber local neu, weg, verschoben oder geändert sind |
| `orphansRecovered`       | in die Wiederherstellungsgruppe verschobene Einträge und Gruppen       |
| `fieldConflicts`         | siehe 5.1                                                              |
| `externalEdits`          | Einträge (beider Seiten), die laut FieldTimes extern geändert wurden   |

### 5.7 Abgleich mit dem Server: Einstellungen der Server-Datei gewinnen

Ein Client führt beim Abgleich nicht `mergeVaults(local, server)` aus, sondern
`mergeVaults(local′, server)`. `local′` ist `local`, in das vorher aus der Server-Datei
übernommen wurde:

- die KDBX-Einstellungen (`settings`: Verschlüsselung, Kompression, Schlüsselableitung samt
  Parametern, KDBX-Nebenversion, öffentliches CustomData des Headers),
- `HistoryMaxItems` und `HistoryMaxSize`,
- die unbekannten Meta-Elemente (`meta.unknown`, z. B. `<MemoryProtection>`,
  `<DatabaseDescription>`),
- die unbekannten Elemente von `<Root>` (`rootUnknown`).

Alles andere bleibt von `local`. Referenz: `adoptServerSettings` in `core/src/sync/sync.ts`.
Grund (PROJECT-CONTEXT, entschieden 2026-10-15): Für diese Angaben ohne Zeitstempel gewinnt die
Fassung der Server-Datei. `mergeVaults` selbst nimmt sie von local (5.5); ohne diesen Schritt
schriebe ein Gerät mit älterer Fassung im Speicher z. B. eine in KeePassXC verstärkte
Schlüsselableitung oder geänderte Verlaufsgrenzen zurück und kürzte den Verlauf nach seinen
alten Grenzen.

## 6. Bearbeiten

Ownwarden ändert eine Datenbank nur über `core/src/merge/vault-ops.ts`: wirksame
Feld-Zeitstempel ermitteln (übernimmt fremde Änderungen), vorherige Fassung in den Verlauf
(nicht beim Verschieben), `lastModification` und für **jedes geänderte Feld** `t = jetzt`,
neu versiegeln. Verschieben setzt `parent`, `locationChanged` und `lastModification` (wie
KeePassXC). Was nur sekundengenau verglichen wird (Gruppe umbenennen/verschieben,
`RecycleBinChanged`), bekommt mindestens die **nächste ganze Sekunde** nach der bisherigen
Zeit – sonst wäre eine Änderung in derselben Sekunde ein Gleichstand und könnte gegen die
ältere Fassung verlieren. Endgültig löschen: Lösch-Vermerk mit `jetzt` (bei Gruppen auch für alles darin).
Passkeys nur als Ganzes. Tags mit `,` oder `;` sind verboten (KeePass trennt daran).
„Jetzt“ liefert eine monotone Uhr: nie kleiner als der größte Zeitstempel der Datenbank
(Änderungs-, Verschiebe-, Lösch-, Feld- und Meta-Zeiten; nicht Ablauf, Zugriff, Erstellung)
+ 1 ms und nie kleiner als der letzte gelieferte Wert + 1 ms. Zeiten außerhalb des
KDBX-Bereichs (siehe Abschnitt 3) zählen dabei nicht. Die Uhr liefert nie mehr als
253402300799000: Am Ende des KDBX-Bereichs bleibt sie stehen (dann entscheidet bei gleicher
Zeit die Gleichstand-Regel).

**Zeichen, die KDBX nicht speichern kann, werden abgelehnt** (Fehler, in der Referenz ein
`RangeError` mit deutscher Meldung, die den Wert nicht nennt) – nie still entfernt oder
ersetzt. Sonst verlöre der Nutzer unbemerkt Daten, und das Modell im Speicher wiche von der
Datei ab: Jeder Abgleich schriebe erneut (mit Sicherungskopie). Abgelehnt werden

- in **ungeschütztem Text** – Werte ungeschützter Felder (auch Passkey-Attribute), Namen von
  Feldern und Anhängen, Tags, CustomData-Schlüssel und -Werte, Gruppennamen, Farben,
  OverrideURL – die in XML 1.0 verbotenen Zeichen U+0000–U+0008, U+000B, U+000C,
  U+000E–U+001F, U+FFFE, U+FFFF und einzelne (ungepaarte) UTF-16-Surrogate. Genau diese
  entfernt der KDBX-Writer (`core/src/kdbx/xml-dom.ts`, `stripInvalidXmlChars`); KeePassXC
  liest sie nicht einmal als `&#n;`.
- in **geschützten Werten** nur einzelne UTF-16-Surrogate: Diese Werte stehen verschlüsselt in
  der Datei, aber UTF-8 kennt keine einzelnen Surrogate (sie würden zu U+FFFD). Tab, LF, CR
  und andere Steuerzeichen bleiben dort erhalten.

Geprüft wird nur, was eine Änderung neu setzt (geänderte Felder, neue Namen); Werte, die
schon so in der Datenbank stehen, sperren keine anderen Änderungen.

---

## 7. Format der Testfälle (`merge-cases/*.json`)

Dateiname = `name` + `.json`. Ein Testfall:

```json
{
  "name": "02-gleiches-feld",
  "description": "… (deutsch)",
  "now": 1700000100000,
  "local":  { …Datenbank… },
  "remote": { …Datenbank… },
  "expected": { …Datenbank… },
  "expectedReport": { …Teil des Berichts… },
  "expectedReportSwapped": { …Teil des Berichts bei vertauschten Seiten… }
}
```

`now` (optional, Standard `1700001000000`) ist `MergeOptions.now`. Es muss eine gültige Zeit
im Sinne von Abschnitt 3 sein (sonst bricht der Merge mit einem Fehler ab, statt ungültige
Zeiten in die Datenbank zu schreiben).

### 7.1 Namen statt UUIDs

UUIDs stehen als lesbare Namen im JSON. Abbildung Name → UUID:

- `"@recovery"` → Wiederherstellungsgruppe `T3dud2FyZGVuUmVjb3Zlcg==`
- `"b64:<Base64>"` → die UUID wörtlich
- sonst: Base64 (mit `=`) der ersten 16 Byte von SHA-256(UTF-8(Name)).
  Beispiel: `"root"` → `SBNJTRN+FjG7owHVrKtuew==`.

### 7.2 Datenbank

| Schlüssel              | Bedeutung (Standardwert)                                                  |
|------------------------|---------------------------------------------------------------------------|
| `root`                 | Name der Wurzelgruppe (`"root"`)                                          |
| `rootName`             | Anzeigename der Wurzel (`"Root"`)                                         |
| `rootLastModification` | alle Zeiten der Wurzel (`1600000000000`)                                  |
| `databaseName`, `databaseNameChanged` | Meta (`""`, `1600000000000`)                               |
| `recycleBin`           | Name der Papierkorb-Gruppe; `null` = Papierkorb aus; fehlt = an, ohne Gruppe |
| `recycleBinChanged`    | (`1600000000000`)                                                         |
| `historyMaxItems`, `historyMaxSize` | Meta (`10`, `-1`)                                            |
| `groups`               | Liste von Gruppen; Reihenfolge = Reihenfolge unter derselben Elterngruppe |
| `entries`              | Liste von Einträgen; Reihenfolge = Reihenfolge in derselben Gruppe        |
| `deleted`              | Lösch-Vermerke `[{"uuid": Name, "time": ms}]`                             |

Sonstige Meta-Werte: Generator `Ownwarden`, keine Icons, kein CustomData. KDBX-Einstellungen
spielen keine Rolle.

**Gruppe:** `uuid` (Name), `name` (Standard = uuid-Name), `parent` (Standard = Wurzel),
`notes` (`""`), `lastModification` (`1600000000000`), `locationChanged` (= lastModification).
Erstellung = min(lastModification, locationChanged), letzter Zugriff = lastModification,
Icon 48, keine Tags/CustomData/unbekannten Elemente, kein Ablauf.

**Eintrag:**

| Schlüssel          | Bedeutung (Standardwert)                                                     |
|--------------------|------------------------------------------------------------------------------|
| `uuid`             | Name                                                                         |
| `parent`           | Gruppe (Wurzel)                                                              |
| `lastModification` | (`1600000000000`)                                                            |
| `locationChanged`  | (= lastModification)                                                         |
| `creation`         | (= min(lastModification, locationChanged))                                   |
| `fields`           | `{"Name": "Wert"}` – genau diese `<String>`-Felder, in dieser Reihenfolge     |
| `protected`        | Namen der geschützten Felder (`[]`)                                          |
| `attachments`      | `{"Name": Inhalt}`; Inhalt = UTF-8-Text, oder `"base64:<Base64>"` für Bytes; Schutz-Flag immer an |
| `tags`             | (`[]`)                                                                       |
| `iconId`           | (`0`)                                                                        |
| `customIcon`       | Name der Icon-UUID (keins)                                                   |
| `expiry`           | Ablaufzeit in ms → Expires = True (fehlt: Expires = False, ExpiryTime = lastModification) |
| `customData`       | `{"Key": "Wert"}`, ohne LastModificationTime (`{}`)                          |
| `foregroundColor`, `backgroundColor`, `overrideUrl` | (`""`)                                      |
| `qualityCheck`     | `false` → QualityCheck = False (sonst nicht gesetzt)                         |
| `unknown`          | unbekannte XML-Elemente als kompakter Text (`[]`)                            |
| `history`          | Liste früherer Fassungen, älteste zuerst (`[]`)                              |
| `fieldTimes`       | `null`/fehlt = **keine** FieldTimes (nie von Ownwarden geschrieben); sonst `{"FieldKey": t}` (siehe unten) |
| `external`         | Änderung durch ein anderes Programm NACH dem Versiegeln (siehe unten)        |

Übrige Zeiten: letzter Zugriff = lastModification, Nutzungszähler 0.

**Verlaufs-Fassung:** `lastModification` (Pflicht; alle Zeiten der Fassung) und dieselben
Inhalts-Schlüssel wie ein Eintrag (`fields`, `protected`, `attachments`, `tags`, `iconId`,
`customIcon`, `expiry`, `customData`, Farben, `overrideUrl`, `qualityCheck`, `unknown`).
UUID = die des Eintrags; keine FieldTimes, kein Verlauf.

**`fieldTimes`** bedeutet: „Ownwarden hat genau diesen Zustand mit diesen Zeiten versiegelt.“
Der Läufer baut den Eintrag (Inhalt und Verlauf) und versiegelt ihn dann (Abschnitt 3):
jedes vorhandene Feld bekommt `t` aus `fieldTimes`, fehlt es dort, die Basiszeit
(`lastModification`, für `parent` `locationChanged`); jeder Schlüssel in `fieldTimes`, dessen
Feld nicht vorhanden ist, wird zum Lösch-Marker. `{}` = alle Felder zur Basiszeit.

**`external`** wird nach dem Versiegeln angewandt (die FieldTimes bleiben stehen – genau wie
bei KeePassXC):

| Schlüssel          | Wirkung                                                                  |
|--------------------|--------------------------------------------------------------------------|
| `lastModification` | Pflicht: neue `times.lastModification`                                   |
| `set`              | `{"Name": "Wert"}` setzen; geschützt, wenn in `protected` genannt        |
| `protected`        | Namen für `set`                                                          |
| `remove`           | Namen entfernen                                                          |
| `attachments`      | `{"Name": Inhalt oder null}` setzen bzw. (null) entfernen               |
| `tags`, `iconId`   | ersetzen                                                                 |
| `parent`           | Eintrag liegt in dieser Gruppe; `locationChanged` = `external.locationChanged` (Standard: `external.lastModification`) |
| `addHistory`       | `true`: vorher die bisherige Fassung (ohne CustomData, wie KeePassXC) an den Verlauf anhängen |

### 7.3 Erwartung (`expected`)

Gleiches Format wie eine Datenbank. Verglichen wird:

- **Gruppen** (ohne Wurzel), genau diese Menge: Name, Elterngruppe, Notizen; Zeiten nur, wenn
  angegeben (`lastModification`, `locationChanged`).
- **Einträge**, genau diese Menge: Gruppe, `fields` (leere Standardfelder zählen als nicht
  vorhanden, egal ob angegeben), `protected` (nur unter den vorhandenen Feldern), Anhänge,
  Tags (als sortierte Menge), Icon, Ablauf, CustomData (ohne `Ownwarden.FieldTimes` und
  `_LAST_MODIFIED`), Farben, OverrideURL, QualityCheck, bedeutsame unbekannte Elemente.
  Nur wenn angegeben: `lastModification`, `locationChanged`, `creation`;
  `fieldTimes` = **wirksame** Feld-Zeitstempel (Abschnitt 4) der genannten Schlüssel – ist
  das Feld in der Erwartung nicht vorhanden, ist ein Lösch-Marker mit dieser Zeit gemeint;
  das Ergebnis muss dann außerdem versiegelt sein;
  `history` = Liste `[{lastModification, fields}]` in dieser Reihenfolge; nennt ein
  Verlaufseintrag der Erwartung `unknown`, wird bei ihm auch die Liste der unbekannten
  Elemente **roh** verglichen (auch das Standard-AutoType).
- **Lösch-Vermerke**, genau diese Menge mit diesen Zeiten.
- `recycleBin` und `databaseName` nur, wenn angegeben.

### 7.4 Bericht

`expectedReport` nennt nur die zu prüfenden Angaben (Abschnitt 5.6). `fieldConflicts` ist eine
Menge von `{"entry": Name, "field": FieldKey, "winner": "local"|"remote", "tieBreak": bool}`,
`externalEdits` eine Menge von Namen. Bei **vertauschten Seiten** gilt `expectedReportSwapped`,
falls vorhanden; sonst werden nur die richtungsunabhängigen Angaben aus `expectedReport` geprüft
(`entriesDeleted`, `entriesResurrected`, `orphansRecovered`, `fieldConflicts` mit getauschtem
`winner`, `externalEdits`).

### 7.5 Was der Läufer zusätzlich prüft

In jeder Richtung: Die Eingaben bleiben unverändert; keine UUID ist zugleich vorhanden und
gelöscht; keine UUID kommt doppelt vor; `merge(m, m)`, `merge(m, remote)` und
`merge(m, local)` (mit demselben `now`) ergeben wieder die Erwartung.

## 8. Prüfwerte (`field-vectors.json`)

Liste von `{name, description, entry, fields, fieldTimesJson?}`: `entry` im Eintrags-Format
aus 7.2 (Gruppe = `entry.parent`, Standard Wurzel). `fields` = **alle** vorhandenen Felder
mit kanonischem Wert (Hex) und Fingerabdruck. `fieldTimesJson` = der genaue Text von
`Ownwarden.FieldTimes` nach dem Versiegeln.

## 9. Die Testfälle

| Datei | Inhalt |
|-------|--------|
| 01-verschiedene-felder | verschiedene Felder auf beiden Seiten geändert |
| 02-gleiches-feld | dasselbe Feld, neuere gewinnt, ältere im Verlauf |
| 03-gleicher-zeitstempel | Gleichstand, feste Regel (in beiden Richtungen gleich) |
| 04-entfernt-neuer-gegen-geaendert | Feld entfernt (neuer) gegen geändert (älter) |
| 05-geaendert-neuer-gegen-entfernt | Feld geändert (neuer) gegen entfernt (älter) |
| 06-umbenannt-und-anderes-feld | Feld umbenannt + anderes Feld auf der anderen Seite |
| 07-geloescht-neuer-gegen-geaendert | Eintrag gelöscht (neuer) gegen geändert |
| 08-geaendert-neuer-gegen-geloescht | geändert (neuer) gegen gelöscht: wiederbelebt |
| 09-gleiche-sekunde-loeschung-gewinnt | Löschung und Änderung in derselben Sekunde |
| 10-papierkorb-gegen-geaendert | in den Papierkorb verschoben gegen geändert |
| 11-verschoben-gegen-geaendert | in andere Gruppe verschoben gegen geändert |
| 12-gruppe-geloescht-eintrag-offline | Gruppe gelöscht, offline angelegter Eintrag → Wiederherstellungsgruppe |
| 13-gruppe-geloescht-eintrag-danach | Gruppe gelöscht, danach Eintrag darin angelegt → Gruppe bleibt |
| 14-keepassxc-ohne-fieldtimes | KeePassXC-Eintrag ohne FieldTimes gegen Ownwarden-Änderung |
| 15-veraltete-fieldtimes-extern | veraltete FieldTimes, externe Änderung per Fingerabdruck erkannt |
| 16-neue-eintraege-beide-seiten | neue Einträge auf beiden Seiten |
| 17-passkey-als-einheit | Passkey als eine Einheit |
| 18-anhaenge | Anhänge: verschiedene Namen, derselbe Name geändert |
| 19-offline-geraet | Gerät mit alten Änderungen |
| 20-tags-und-icon | Tags und Icon |
| 21-verlauf-gekuerzt | Verlauf vereinigt und auf HistoryMaxItems gekürzt |
| 22-gruppe-beidseitig-umbenannt | Gruppe auf beiden Seiten umbenannt |
| 23-gruppen-zyklus | Gruppen-Verschiebungen bilden einen Kreis |
| 24-unbekannte-loeschvermerke | Lösch-Vermerke für unbekannte UUIDs bleiben |
| 25-identisch | gleiche Datenbanken, leerer Bericht |
| 26-keepassxc-speichert-ohne-aenderung | KeePassXC legt leere Standardfelder an – keine Änderung |
| 27-beidseitig-verschoben | auf beiden Seiten in verschiedene Gruppen verschoben |
| 28-keepassxc-verschiebt | KeePassXC verschiebt (Fingerabdruck von parent) gegen Ownwarden-Änderung |
| 29-datenbankname-und-papierkorb | Meta: Datenbankname und Papierkorb |
| 30-gleiche-sekunde-speicher-gegen-datei | Speicher (ms) gegen Datei (s): Gruppe, Datenbankname, Eintrag ohne FieldTimes in derselben Sekunde |
| 31-verlauf-gleiche-sekunde | dieselbe Fassung aus Speicher (ms) und Datei (s) steht nur einmal im Verlauf |
| 32-ohne-fieldtimes-neuere-entfernt | beide Seiten ohne FieldTimes: Entfernungen der neueren Seite (ohne Verlauf) gewinnen |
| 33-verlauf-doppelt-rohdaten | doppelte Verlaufsfassung, nur das Standard-AutoType verschieden: feste Wahl über alle Rohdaten |
| 34-papierkorb-gleiche-sekunde | Papierkorb in derselben Sekunde verschieden gewählt: Gleichstand über `encodeParts([an/aus, UUID-Text])` |

## 10. Bekannte Grenzen

- Einträge **ohne** FieldTimes und **ohne** Verlauf (in KeePassXC angelegt und nur ohne
  Verlaufseintrag geändert, z. B. per „in den Papierkorb“) gelten als komplett zur
  `lastModification` geändert; eine ältere Ownwarden-Änderung an einem anderen Feld dieses
  Eintrags verliert dann.
- Haben **beide** Seiten keine FieldTimes, entscheidet die neuere Fassung auch, welche Felder
  fehlen (5.1). Ein Feld, das auf der älteren Kopie gleichzeitig in KeePassXC neu angelegt
  wurde, verliert dann gegen die neuere Fassung, die es nicht kennt (es bleibt im Verlauf).
  Ist nur EINE Seite versiegelt, gilt die Regel nicht (die versiegelte Seite kann das Feld über
  Ownwarden angelegt haben): Ein in KeePassXC ohne Verlaufseintrag entferntes Feld eines
  unversiegelten Eintrags kommt dann über eine versiegelte Kopie, die es hat, zurück.
- Ein entfernter Wert bleibt – wie jede überschriebene Fassung (5.1) – im Verlauf des
  Ergebnisses. Wer ein Geheimnis in KeePassXC entfernt und den Verlauf löscht, bekommt es über
  ein Gerät mit einer älteren Kopie wieder in den Verlauf (nicht in die aktuelle Fassung).
- Ändert KeePassXC einen versiegelten Eintrag mehrmals, bekommen alle geänderten Felder die
  Zeit der letzten Änderung.
- Änderungen innerhalb derselben Sekunde sind über KDBX-Zeiten nicht unterscheidbar
  (Löschen gegen Ändern: die Löschung gewinnt).
- Die Kürzung nach `HistoryMaxSize` ist nicht in jedem Fall stabil: Ein erneuter Abgleich mit
  einer Eingabe kann eine kleine, früher weggefallene Fassung wieder aufnehmen.
- Angaben, die `mergeVaults` von local übernimmt (Verlaufsgrenzen, unbekannte Meta- und
  Root-Elemente, KDBX-Einstellungen), hängen von der Rolle der Seiten ab. Beim Abgleich ist das
  ohne Folgen, weil der Client vorher die Werte der Server-Datei einsetzt (5.7): Ändert jemand
  diese Angaben in KeePassXC, bleibt die Änderung erhalten. Ändert ein Gerät sie selbst, setzt
  sich die Server-Fassung durch (Ownwarden ändert sie in Version 1 nicht).
- Zwei Fassungen derselben Sekunde, die sich nur in CustomData oder anderen nicht kanonischen
  Kleinigkeiten unterscheiden, zählen im Verlauf als eine; welche bleibt, legt 5.1 fest.
