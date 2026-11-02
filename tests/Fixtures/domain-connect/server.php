<?php

declare(strict_types=1);

/*
 * Router for the StreamTransport loopback test (`php -S 127.0.0.1:<port> server.php`).
 * Test-only; it serves nothing real.
 */

$uri = $_SERVER['REQUEST_URI'] ?? '/';
$path = is_string($uri) ? parse_url($uri, PHP_URL_PATH) : '/';

switch ($path) {
    case '/ok':
        header('Content-Type: application/json');
        echo '{"ok":true}';
        break;
    case '/redirect':
        header('Location: /ok', true, 302);
        break;
    case '/big':
        header('Content-Type: application/json');
        echo str_repeat('x', 70 * 1024);
        break;
    case '/slow':
        sleep(3);
        echo '{"late":true}';
        break;
    default:
        http_response_code(404);
        echo 'not found';
}
