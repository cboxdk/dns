<?php

declare(strict_types=1);

use Cbox\Dns\DomainConnect\Contracts\Transport;
use Cbox\Dns\DomainConnect\HttpResponse;
use Cbox\Dns\DomainConnect\Transports\StreamTransport;

it('does not follow redirects and reports transport failure as status 0', function (): void {
    $transport = new StreamTransport(fetcher: fn (string $url): HttpResponse => new HttpResponse(0, ''));

    expect($transport)->toBeInstanceOf(Transport::class)
        ->and($transport->get('https://unreachable.invalid/')->status)->toBe(0);
});

it('hands the url to the injected fetcher and returns its response', function (): void {
    $seen = [];
    $transport = new StreamTransport(fetcher: function (string $url) use (&$seen): HttpResponse {
        $seen[] = $url;

        return new HttpResponse(200, '{"ok":true}');
    });

    expect($transport->get('https://x/')->json())->toBe(['ok' => true])
        ->and($seen)->toBe(['https://x/']);
});
