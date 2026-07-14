<?php

declare(strict_types=1);

use Cbox\Dns\Propagation\PublicResolver;
use Cbox\Dns\Propagation\PublicResolvers;

it('exposes the full named registry of well-known public resolvers', function (): void {
    $all = PublicResolvers::all();

    expect($all)->each->toBeInstanceOf(PublicResolver::class);

    $ips = array_map(static fn (PublicResolver $r): string => $r->ip, $all);

    expect($ips)->toContain(
        '8.8.8.8', '8.8.4.4',            // Google
        '1.1.1.1', '1.0.0.1',            // Cloudflare
        '9.9.9.9',                       // Quad9
        '208.67.222.222', '208.67.220.220', // OpenDNS
        '4.2.2.1', '4.2.2.2',            // Level3
        '64.6.64.6',                     // Verisign
        '94.140.14.14',                  // AdGuard
        '84.200.69.80',                  // DNS.Watch
        '156.154.70.1',                  // Neustar/UltraDNS
        '77.88.8.8',                     // Yandex
        '8.26.56.26',                    // Comodo
    );
});

it('labels every registry entry with a provider name', function (): void {
    foreach (PublicResolvers::all() as $resolver) {
        expect($resolver->label)->not->toBe('')
            ->and($resolver->name)->not->toBe('');
    }

    $google = array_values(array_filter(
        PublicResolvers::all(),
        static fn (PublicResolver $r): bool => $r->ip === '8.8.8.8',
    ))[0];

    expect($google->label)->toBe('Google Public DNS');
});

it('exposes the lean default panel already used by the checker', function (): void {
    $default = PublicResolvers::default();

    expect($default)->each->toBeInstanceOf(PublicResolver::class);

    $ips = array_map(static fn (PublicResolver $r): string => $r->ip, $default);

    expect($ips)->toBe(['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1', '9.9.9.9', '208.67.222.222'])
        ->and(count($default))->toBeLessThan(count(PublicResolvers::all()));
});
