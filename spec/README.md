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
speichern.) Feldschlüssel, die das Feld-Modell
nicht kennt (z. B. `s:KPEX_PASSKEY_…`, `cd:_LAST_MODIFIED`, `s:` ohne Namen), werden
übersprungen.

**Versiegeln** (nach jeder Änderung durch Ownwarden und nach jedem Zusammenführen): für
jedes vorhandene Feld `{"t", "h"}` mit frischem Fingerabdruck, für jedes bekannte entfernte
Feld `{"t", "d":1}`; `w` = `times.lastModification`. Lösch-Marker werden nie gelöscht
(sonst brächte ein Gerät, das lange offline war, das Feld zurück).

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

## 5. Zusammenführen (`mergeVaults(local, remote, now)`)

Reine Funktion: Die Eingaben werden nicht verändert. Inhaltlich hängt das Ergebnis nicht
davon ab, welche Seite local ist (nur die Reihenfolge von Geschwistern, die von local
übernommenen Meta-Angaben und das Feld `winner` im Bericht).

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
  einmal. Behalten wird die mit dem größeren Rohdaten-Fingerabdruck **über die auf ganze
  Sekunden abgerundeten Zeiten** (auch Ablaufzeit und `LastModificationTime` von
  CustomData), bei Gleichheit die mit dem größeren Rohdaten-Fingerabdruck über die genauen
  Zeiten. Rohdaten-Fingerabdruck = Fingerabdruck wie in Abschnitt 3 über
  `encodeParts([key1, exakt1, key2, exakt2, …, creation, lastModification, lastAccess, expiry, usageCount, locationChanged, expires])`
  mit allen vorhandenen Feldern nach Schlüssel sortiert; als Text verglichen. Sortiert nach
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

### 5.2 Doppelte UUIDs in einer Datei

Kommt eine Eintrags- oder Gruppen-UUID in EINER Datei mehrfach vor (der XML-Leser erkennt das
nicht), werden die Vorkommen vorher wie zwei Seiten zusammengeführt (das erste Vorkommen
als local). Eine Untergruppe mit der UUID der Wurzel wird Teil der Wurzel.
Haben beide Seiten verschiedene Wurzel-UUIDs, gelten beide Wurzeln als dieselbe Gruppe; ihre
UUID im Ergebnis ist die kleinere.

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
  größere Eltern-UUID (Text). Die Wurzel hat keine.

Zeiten: `creation` min, `lastModification`/`lastAccess`/`usageCount` max, `locationChanged`
vom Gewinner der Elterngruppe (haben beide Seiten dieselbe Elterngruppe: das Maximum), Ablauf vom
Gewinner der Eigenschaften.

**Zyklen** (local schiebt A unter B, remote B unter A): In jedem Kreis kommt die Gruppe mit
der kleinsten `locationChanged` (ganze Sekunden; Gleichstand: kleinere UUID) direkt unter die
Wurzel.

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
  nach `DatabaseNameChanged`, Papierkorb (an/aus + UUID) nach `RecycleBinChanged`
  (Gleichstand jeweils: größerer Wert; bei gleichem Wert auf beiden Seiten bekommt das Ergebnis
  die spätere der beiden Zeiten). Eigene Icons: Vereinigung nach UUID, bei beiden Seiten
  gewinnt die neuere `LastModificationTime` (fehlend = −∞; Gleichstand: größeres
  `encodeParts([daten, name oder "", lastModified oder ""])`); ein Icon mit neuerem
  Lösch-Vermerk fällt weg, außer ein Eintrag (auch im Verlauf) oder eine Gruppe benutzt es.
  CustomData: Vereinigung, bei gleichem Schlüssel gewinnt die neuere `LastModificationTime`
  (fehlend = −∞), bei Gleichstand – in KDBX 4.0 der Normalfall – das größere
  `encodeParts([wert, lastModified oder ""])` (nicht local: sonst behielte jedes Gerät seinen
  Wert und schriebe ihn immer wieder zurück). Verlaufsgrenzen, unbekannte Elemente und
  KDBX-Einstellungen von local (KDBX-Nebenversion = Maximum). Generator `Ownwarden`.
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
KDBX-Bereichs (siehe Abschnitt 3) zählen dabei nicht.

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
  `history` = Liste `[{lastModification, fields}]` in dieser Reihenfolge.
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

## 10. Bekannte Grenzen

- Einträge **ohne** FieldTimes und **ohne** Verlauf (in KeePassXC angelegt und nur ohne
  Verlaufseintrag geändert, z. B. per „in den Papierkorb“) gelten als komplett zur
  `lastModification` geändert; eine ältere Ownwarden-Änderung an einem anderen Feld dieses
  Eintrags verliert dann.
- Ändert KeePassXC einen versiegelten Eintrag mehrmals, bekommen alle geänderten Felder die
  Zeit der letzten Änderung.
- Änderungen innerhalb derselben Sekunde sind über KDBX-Zeiten nicht unterscheidbar
  (Löschen gegen Ändern: die Löschung gewinnt).
- Die Kürzung nach `HistoryMaxSize` ist nicht in jedem Fall stabil: Ein erneuter Abgleich mit
  einer Eingabe kann eine kleine, früher weggefallene Fassung wieder aufnehmen.
- Meta-Angaben, die von local übernommen werden (Verlaufsgrenzen, unbekannte Elemente,
  KDBX-Einstellungen), hängen von der Rolle der Seiten ab. Folge: Ändert jemand diese Angaben
  in KeePassXC, schreibt ein Gerät mit älterer Fassung im Speicher beim nächsten Abgleich
  seine Fassung zurück.
- Zwei Fassungen derselben Sekunde, die sich nur in CustomData oder anderen nicht kanonischen
  Kleinigkeiten unterscheiden, zählen im Verlauf als eine.
