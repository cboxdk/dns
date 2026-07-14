<?php

declare(strict_types=1);

use Cbox\Dns\Support\IpAddress;

it('accepts genuinely public addresses', function (string $ip): void {
    expect(IpAddress::isPublic($ip))->toBeTrue();
})->with([
    '8.8.8.8',
    '93.184.216.34',
    '2606:4700:4700::1111',
    '100.128.0.1',            // just outside the 100.64.0.0/10 CGNAT block
]);

it('rejects private, reserved, and internal addresses', function (string $ip): void {
    expect(IpAddress::isPublic($ip))->toBeFalse();
})->with([
    '127.0.0.1',              // loopback
    '10.0.0.5',              // RFC1918
    '192.168.1.1',           // RFC1918
    '172.16.0.1',            // RFC1918
    '169.254.169.254',       // link-local / cloud metadata
    '100.64.0.1',            // RFC 6598 CGNAT shared space
    '::1',                   // IPv6 loopback
    'fe80::1',               // IPv6 link-local
    'fc00::1',               // IPv6 ULA
    '::ffff:169.254.169.254', // IPv4-mapped metadata
    '::ffff:10.0.0.1',       // IPv4-mapped RFC1918
    '64:ff9b::a00:1',        // NAT64 embedding 10.0.0.1
    '2002:0a00:0001::',      // 6to4 embedding 10.0.0.1
]);
