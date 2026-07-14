<?php

declare(strict_types=1);

use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Propagation\PropagationChecker;
use Cbox\Dns\Propagation\PublicResolvers;
use Cbox\Dns\Propagation\ResolverResult;
use Cbox\Dns\Resolvers\AuthoritativeResolver;
use Cbox\Dns\Testing\FakeResolver;

/**
 * Stub example.com's authoritative A (via NS + glue) plus the recursive panel so a
 * cross-provider check runs fully offline.
 */
function providerZone(string $answer): FakeResolver
{
    return (new FakeResolver)
        ->stub('example.com', RecordType::NS, ['ns1.example.com'])
        ->stub('ns1.example.com', RecordType::A, ['192.0.2.1'])
        ->stub('www.example.com', RecordType::A, [$answer], nameserver: '192.0.2.1')
        ->stub('www.example.com', RecordType::A, [$answer]); // recursive panel fallback
}

it('defaults the bare panel results to a null provider label', function (): void {
    $fake = providerZone('93.184.216.34');

    $report = (new PropagationChecker($fake, new AuthoritativeResolver($fake), ['8.8.8.8']))
        ->check('www.example.com', RecordType::A, 'example.com');

    expect($report->results[0]->label)->toBeNull()
        ->and($report->results[0]->nameserver)->toBe('8.8.8.8');
});

it('labels each result with its provider name in the wider check', function (): void {
    $fake = providerZone('93.184.216.34');

    $report = (new PropagationChecker($fake, new AuthoritativeResolver($fake)))
        ->checkAcrossProviders('www.example.com', RecordType::A, 'example.com');

    expect($report->results)->toHaveCount(count(PublicResolvers::all()));

    $labels = array_map(static fn (ResolverResult $r): ?string => $r->label, $report->results);

    expect($labels)->toContain('Google Public DNS', 'Cloudflare', 'Quad9', 'Yandex DNS')
        ->and($labels)->not->toContain(null);

    // Every registered provider IP is polled and labelled.
    $byIp = [];
    foreach ($report->results as $result) {
        $byIp[$result->nameserver] = $result->label;
    }

    expect($byIp['1.1.1.1'])->toBe('Cloudflare')
        ->and($byIp['77.88.8.8'])->toBe('Yandex DNS');
});

it('keeps the ResolverResult constructor backward compatible (label defaults null)', function (): void {
    $result = new ResolverResult('8.8.8.8', ['93.184.216.34'], true);

    expect($result->label)->toBeNull();
});
