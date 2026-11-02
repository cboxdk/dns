<?php

declare(strict_types=1);

use Cbox\Dns\DomainConnect\Contracts\Transport;
use Cbox\Dns\DomainConnect\HttpResponse;
use Cbox\Dns\DomainConnect\Transports\StreamTransport;

it('does not follow redirects and reports transport failure as status 0', function (): void {
    $transport = new StreamTransport(fetcher: fn (string $url, array $options): HttpResponse => new HttpResponse(0, ''));

    expect($transport)->toBeInstanceOf(Transport::class)
        ->and($transport->get('https://unreachable.invalid/')->status)->toBe(0);
});

it('hands the url and context options to the injected fetcher and returns its response', function (): void {
    $seen = [];
    $transport = new StreamTransport(fetcher: function (string $url, array $options) use (&$seen): HttpResponse {
        $seen[] = [$url, $options];

        return new HttpResponse(200, '{"ok":true}');
    });

    expect($transport->get('https://x/')->json())->toBe(['ok' => true])
        ->and($seen[0][0])->toBe('https://x/')
        ->and($seen[0][1]['http']['follow_location'])->toBe(0)
        ->and($seen[0][1])->not->toHaveKey('ssl');
});

it('connects to a pinned IPv4 address while verifying TLS for the original host', function (): void {
    $seen = [];
    $transport = new StreamTransport(fetcher: function (string $url, array $options) use (&$seen): HttpResponse {
        $seen = [$url, $options];

        return new HttpResponse(200, '');
    });

    $transport->get('https://dc.example:8443/connect/v2/acme.example/settings', '203.0.113.10');

    expect($seen[0])->toBe('https://203.0.113.10:8443/connect/v2/acme.example/settings')
        ->and($seen[1]['ssl'])->toBe(['peer_name' => 'dc.example', 'verify_peer' => true, 'verify_peer_name' => true])
        ->and($seen[1]['http']['header'])->toContain("Host: dc.example:8443\r\n");
});

it('brackets a pinned IPv6 address and sends the bare host when there is no port', function (): void {
    $seen = [];
    $transport = new StreamTransport(fetcher: function (string $url, array $options) use (&$seen): HttpResponse {
        $seen = [$url, $options];

        return new HttpResponse(200, '');
    });

    $transport->get('https://dc.example/v2/acme.example/settings', '2001:db8::1');

    expect($seen[0])->toBe('https://[2001:db8::1]/v2/acme.example/settings')
        ->and($seen[1]['ssl']['peer_name'])->toBe('dc.example')
        ->and($seen[1]['http']['header'])->toContain("Host: dc.example\r\n");
});
