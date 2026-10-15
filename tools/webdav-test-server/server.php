<?php

/**
 * NUR FÜR TESTS: WebDAV-Server für die Tests von Ownwarden (core/src/sync/).
 *
 * Start (aus diesem Ordner, nach "composer install"):
 *
 *   OWNWARDEN_WEBDAV_DATA_DIR=/pfad/zu/daten \
 *   OWNWARDEN_WEBDAV_USER=test OWNWARDEN_WEBDAV_PASSWORD=test-passwort \
 *   php -S 127.0.0.1:8080 server.php
 *
 * Umgebungsvariablen:
 *   OWNWARDEN_WEBDAV_DATA_DIR    Pflicht. Wurzel des WebDAV-Baums (wird angelegt, falls nötig).
 *   OWNWARDEN_WEBDAV_USER        Pflicht. Benutzername für Basic-Auth.
 *   OWNWARDEN_WEBDAV_PASSWORD    Pflicht. Passwort für Basic-Auth.
 *   OWNWARDEN_WEBDAV_STATE_DIR   Optional. Verwaltungsdaten (ETags, Sperre, halbe Uploads).
 *                                Standard: "<DATA_DIR>.state". Muss im selben Dateisystem
 *                                liegen wie DATA_DIR, sonst ist rename() nicht atomar.
 *
 * Was hier wie bei Nextcloud funktioniert (und warum das für Ownwarden wichtig ist):
 *
 *   1. ETags sind STARK und ändern sich bei JEDEM Schreiben – auch bei zwei Schreibvorgängen
 *      in derselben Sekunde und auch dann, wenn derselbe Inhalt erneut geschrieben wird.
 *      Nextcloud vergibt dafür bei jeder Änderung eine neue Zufallskennung (Datei-Cache);
 *      wir speichern ebenfalls eine Zufallskennung pro Datei im STATE_DIR.
 *      Ein ETag, der nur aus Größe + Änderungszeit (in Sekunden) bestünde, wäre für
 *      bedingtes Schreiben (If-Match) unbrauchbar: Zwei Geräte könnten in derselben Sekunde
 *      schreiben, ohne dass das zweite eine 412 bekommt.
 *   2. Hochgeladene Daten landen zuerst in einer Temporärdatei; erst wenn alles da ist (und
 *      die Größe zum Content-Length-Header passt), wird sie per rename() atomar an die Stelle
 *      der alten Datei gesetzt. Ein abgebrochener Upload lässt die alte Datei also unverändert.
 *      (Nextcloud schreibt dafür "<name>.ocTransferId….part" und prüft die Länge genauso.)
 *   3. If-Match und If-None-Match wertet SabreDAV selbst aus (Server::checkPreconditions),
 *      sofern getETag() den aktuellen ETag liefert. Damit Prüfung und Schreiben nicht von
 *      einer parallelen Anfrage unterbrochen werden, läuft jede Anfrage unter einer
 *      exklusiven Dateisperre (Nextcloud sperrt Dateien während des Schreibens ebenfalls).
 *   4. Antworten auf PUT tragen den neuen ETag sowohl in "ETag" als auch in "OC-ETag".
 *
 * Nicht nachgebildet: Papierkorb, Versionen, Chunked-Upload-API, Freigaben, Sperren (LOCK).
 *
 * Hinweis zum eingebauten PHP-Server ("php -S"): Er liest den kompletten Anfrage-Körper,
 * bevor er dieses Skript startet. Bricht der Client den Upload ab, kommt die Anfrage hier
 * gar nicht an. Die Temporärdatei + rename() (Punkt 2) schützen zusätzlich für den Fall,
 * dass das Skript unter einem anderen Webserver (z. B. Apache mit mod_php) läuft.
 */

declare(strict_types=1);

require __DIR__ . '/vendor/autoload.php';

use Sabre\DAV;

// ---------------------------------------------------------------------------
// Konfiguration
// ---------------------------------------------------------------------------

/** Liest eine Pflicht-Umgebungsvariable; bricht mit 500 ab, wenn sie fehlt. */
function requiredEnv(string $name): string
{
    $value = getenv($name);
    if ($value === false || $value === '') {
        http_response_code(500);
        header('Content-Type: text/plain; charset=utf-8');
        echo "Umgebungsvariable $name fehlt.\n";
        exit;
    }
    return $value;
}

$dataDir = rtrim(requiredEnv('OWNWARDEN_WEBDAV_DATA_DIR'), '/');
$username = requiredEnv('OWNWARDEN_WEBDAV_USER');
$password = requiredEnv('OWNWARDEN_WEBDAV_PASSWORD');
$stateDir = rtrim(getenv('OWNWARDEN_WEBDAV_STATE_DIR') ?: $dataDir . '.state', '/');

foreach ([$dataDir, $stateDir, $stateDir . '/etags', $stateDir . '/uploads'] as $dir) {
    if (!is_dir($dir) && !mkdir($dir, 0700, true) && !is_dir($dir)) {
        http_response_code(500);
        echo "Ordner $dir kann nicht angelegt werden.\n";
        exit;
    }
}

// ---------------------------------------------------------------------------
// ETags
// ---------------------------------------------------------------------------

/**
 * Speichert pro Datei einen zufälligen, starken ETag (wie der Datei-Cache von Nextcloud).
 *
 * Zusätzlich merken wir uns Größe, Änderungszeit und Inode der Datei. Passen diese nicht
 * mehr (jemand hat die Datei außerhalb des Servers geändert, z. B. ein Test direkt im
 * Dateisystem), bekommt die Datei einen neuen ETag. Nextcloud erkennt solche externen
 * Änderungen ähnlich über seinen Datei-Scanner.
 */
final class EtagStore
{
    public function __construct(private readonly string $dir)
    {
    }

    /** Aktueller ETag der Datei; legt einen neuen an, wenn keiner bekannt ist oder die Datei extern geändert wurde. */
    public function get(string $path): string
    {
        $stored = $this->load($path);
        if ($stored !== null && $stored['stat'] === $this->statKey($path)) {
            return $stored['etag'];
        }
        return $this->renew($path);
    }

    /** Vergibt einen neuen ETag (nach jedem Schreiben). */
    public function renew(string $path): string
    {
        $etag = '"' . bin2hex(random_bytes(16)) . '"';
        $record = json_encode(['etag' => $etag, 'stat' => $this->statKey($path)], JSON_THROW_ON_ERROR);
        // Auch die ETag-Datei selbst atomar ersetzen.
        $tmp = $this->file($path) . '.' . bin2hex(random_bytes(4)) . '.tmp';
        file_put_contents($tmp, $record);
        rename($tmp, $this->file($path));
        return $etag;
    }

    /** Vergisst den ETag (nach dem Löschen). */
    public function forget(string $path): void
    {
        @unlink($this->file($path));
    }

    /** @return array{etag: string, stat: string}|null */
    private function load(string $path): ?array
    {
        $raw = @file_get_contents($this->file($path));
        if ($raw === false) {
            return null;
        }
        $record = json_decode($raw, true);
        return is_array($record) && is_string($record['etag'] ?? null) && is_string($record['stat'] ?? null) ? $record : null;
    }

    private function statKey(string $path): string
    {
        clearstatcache(true, $path);
        $stat = @stat($path);
        return $stat === false ? 'missing' : $stat['ino'] . ':' . $stat['size'] . ':' . $stat['mtime'] . ':' . $stat['ctime'];
    }

    private function file(string $path): string
    {
        return $this->dir . '/' . hash('sha256', $path) . '.json';
    }
}

// ---------------------------------------------------------------------------
// Schreiben über Temporärdatei + rename()
// ---------------------------------------------------------------------------

/**
 * Schreibt $data (String oder Stream) atomar nach $target.
 *
 * Ablauf wie bei Nextcloud: erst alles in eine Temporärdatei schreiben, dann die Länge
 * prüfen, dann per rename() an die Zielstelle setzen. Bis zum rename() sieht jeder Leser
 * die alte Datei; schlägt etwas fehl, bleibt die alte Datei unverändert.
 */
function writeAtomically(string $uploadDir, string $target, $data): void
{
    $tmp = $uploadDir . '/' . bin2hex(random_bytes(12)) . '.part';
    $out = fopen($tmp, 'xb');
    if ($out === false) {
        throw new DAV\Exception('Temporärdatei kann nicht angelegt werden.');
    }
    try {
        if (is_resource($data)) {
            $written = stream_copy_to_stream($data, $out);
        } else {
            $written = fwrite($out, (string) ($data ?? ''));
        }
        fflush($out);
        fsync($out);
    } finally {
        fclose($out);
    }

    // Nur bei PUT kennt der Client die erwartete Länge (bei COPY ruft SabreDAV createFile
    // mit einem Stream der Quelldatei auf, da gibt es keinen Content-Length-Header).
    $expected = expectedUploadLength();
    if ($written === false || ($expected !== null && $written !== $expected)) {
        @unlink($tmp);
        throw new DAV\Exception\BadRequest(sprintf(
            'Erwartet wurden %s Bytes, angekommen sind %s Bytes. Upload verworfen, alte Datei unverändert.',
            $expected ?? '?',
            $written === false ? '?' : (string) $written,
        ));
    }

    if (!rename($tmp, $target)) {
        @unlink($tmp);
        throw new DAV\Exception('Datei kann nicht ersetzt werden.');
    }
    clearstatcache(true, $target);
}

/** Content-Length einer PUT-Anfrage, sonst null. */
function expectedUploadLength(): ?int
{
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'PUT') {
        return null;
    }
    $length = $_SERVER['CONTENT_LENGTH'] ?? $_SERVER['HTTP_CONTENT_LENGTH'] ?? null;
    return $length !== null && ctype_digit((string) $length) ? (int) $length : null;
}

/** Wirft 400, wenn ein Name aus der URL kein einfacher Datei- oder Ordnername ist. */
function assertSafeName(string $name): void
{
    if ($name === '' || $name === '.' || $name === '..' || strpbrk($name, "/\\\0") !== false) {
        throw new DAV\Exception\BadRequest('Ungültiger Name.');
    }
}

// ---------------------------------------------------------------------------
// Knoten des WebDAV-Baums
// ---------------------------------------------------------------------------

final class NextcloudLikeFile extends DAV\File
{
    public function __construct(
        private string $path,
        private readonly EtagStore $etags,
        private readonly string $uploadDir,
    ) {
    }

    public function getName()
    {
        return basename($this->path);
    }

    public function setName($name)
    {
        assertSafeName($name);
        $newPath = dirname($this->path) . '/' . $name;
        rename($this->path, $newPath);
        $this->etags->forget($this->path);
        $this->path = $newPath;
        $this->etags->renew($newPath);
    }

    public function get()
    {
        return fopen($this->path, 'rb');
    }

    public function put($data)
    {
        writeAtomically($this->uploadDir, $this->path, $data);
        return $this->etags->renew($this->path);
    }

    public function getSize()
    {
        clearstatcache(true, $this->path);
        return filesize($this->path);
    }

    public function getETag()
    {
        return $this->etags->get($this->path);
    }

    public function getContentType()
    {
        return 'application/octet-stream';
    }

    public function getLastModified()
    {
        clearstatcache(true, $this->path);
        return filemtime($this->path);
    }

    public function delete()
    {
        unlink($this->path);
        $this->etags->forget($this->path);
    }
}

final class NextcloudLikeDirectory extends DAV\Collection
{
    public function __construct(
        private string $path,
        private readonly EtagStore $etags,
        private readonly string $uploadDir,
    ) {
    }

    public function getName()
    {
        return basename($this->path);
    }

    public function setName($name)
    {
        assertSafeName($name);
        $newPath = dirname($this->path) . '/' . $name;
        rename($this->path, $newPath);
        $this->path = $newPath;
    }

    public function getChildren()
    {
        $children = [];
        foreach (scandir($this->path) ?: [] as $name) {
            if ($name !== '.' && $name !== '..') {
                $children[] = $this->nodeFor($this->path . '/' . $name);
            }
        }
        return $children;
    }

    public function getChild($name)
    {
        assertSafeName($name);
        $path = $this->path . '/' . $name;
        if (!file_exists($path)) {
            throw new DAV\Exception\NotFound('Nicht gefunden: ' . $name);
        }
        return $this->nodeFor($path);
    }

    public function childExists($name)
    {
        assertSafeName($name);
        return file_exists($this->path . '/' . $name);
    }

    public function createFile($name, $data = null)
    {
        assertSafeName($name);
        $path = $this->path . '/' . $name;
        writeAtomically($this->uploadDir, $path, $data);
        return $this->etags->renew($path);
    }

    public function createDirectory($name)
    {
        assertSafeName($name);
        mkdir($this->path . '/' . $name, 0700);
    }

    public function getLastModified()
    {
        clearstatcache(true, $this->path);
        return filemtime($this->path);
    }

    public function delete()
    {
        foreach ($this->getChildren() as $child) {
            $child->delete();
        }
        rmdir($this->path);
    }

    private function nodeFor(string $path): DAV\INode
    {
        return is_dir($path)
            ? new self($path, $this->etags, $this->uploadDir)
            : new NextcloudLikeFile($path, $this->etags, $this->uploadDir);
    }
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

// Exklusive Sperre für die ganze Anfrage (siehe Punkt 3 im Kopfkommentar). Sie wird beim
// Ende des Skripts automatisch freigegeben.
$lock = fopen($stateDir . '/server.lock', 'c');
flock($lock, LOCK_EX);

$etags = new EtagStore($stateDir . '/etags');
$root = new NextcloudLikeDirectory($dataDir, $etags, $stateDir . '/uploads');

$server = new DAV\Server($root);
$server->setBaseUri('/');
$server->debugExceptions = false;

$authBackend = new DAV\Auth\Backend\BasicCallBack(
    static fn (string $user, string $pass): bool => hash_equals($username, $user) && hash_equals($password, $pass),
);
$authBackend->setRealm('Ownwarden-Test');
$server->addPlugin(new DAV\Auth\Plugin($authBackend));

// Wie Nextcloud: den neuen ETag nach PUT zusätzlich als "OC-ETag" melden.
$server->on('afterMethod:PUT', static function ($request, $response): void {
    $etag = $response->getHeader('ETag');
    if ($etag !== null) {
        $response->setHeader('OC-ETag', $etag);
    }
});

// Date-Header immer setzen (Ownwarden prüft damit die Geräteuhr).
$server->on('beforeMethod:*', static function ($request, $response): void {
    $response->setHeader('Date', gmdate('D, d M Y H:i:s') . ' GMT');
}, 1);

$server->start();
