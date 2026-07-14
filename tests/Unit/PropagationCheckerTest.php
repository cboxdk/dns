<?php

declare(strict_types=1);

use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Propagation\PropagationChecker;
use Cbox\Dns\Propagation\PropagationStatus;
use Cbox\Dns\Resolvers\AuthoritativeResolver;
use Cbox\Dns\Testing\FakeResolver;

/**
 * Stub the NS + NS-host A so the AuthoritativeResolver resolves example.com's
 * authoritative IP (192.0.2.1), then stub the target A there.
 *
 * @param  list<string>  $authoritativeValues
 */
function zoneWithAuthoritative(array $authoritativeValues): FakeResolver
{
    $fake = (new FakeResolver)
        ->stub('example.com', RecordType::NS, ['ns1.example.com'])
        ->stub('ns1.example.com', RecordType::A, ['192.0.2.1']);

    if ($authoritativeValues !== []) {
        $fake->stub('www.example.com', RecordType::A, $authoritativeValues, nameserver: '192.0.2.1');
    }

    return $fake;
}

$publicPanel = ['8.8.8.8', '1.1.1.1'];

it('reports Propagated when every public resolver agrees with authoritative', function () use ($publicPanel): void {
    $fake = zoneWithAuthoritative(['93.184.216.34']);
    // Stub the public panel to match the authoritative answer.
    foreach ($publicPanel as $ns) {
        $fake->stub('www.example.com', RecordType::A, ['93.184.216.34'], nameserver: $ns);
    }

    $report = (new PropagationChecker($fake, new AuthoritativeResolver($fake), $publicPanel))
        ->check('www.example.com', RecordType::A, 'example.com');

    expect($report->status)->toBe(PropagationStatus::Propagated)
        ->and($report->authoritativeValues)->toBe(['93.184.216.34'])
        ->and($report->results)->toHaveCount(2)
        ->and($report->stale())->toBe([]);
});

it('reports Pending when authoritative is correct but a resolver is stale', function () use ($publicPanel): void {
    $fake = zoneWithAuthoritative(['93.184.216.34']);
    $fake->stub('www.example.com', RecordType::A, ['93.184.216.34'], nameserver: '8.8.8.8');   // caught up
    $fake->stub('www.example.com', RecordType::A, ['198.51.100.9'], nameserver: '1.1.1.1');    // stale

    $report = (new PropagationChecker($fake, new AuthoritativeResolver($fake), $publicPanel))
        ->check('www.example.com', RecordType::A, 'example.com');

    expect($report->status)->toBe(PropagationStatus::Pending)
        ->and($report->stale())->toHaveCount(1)
        ->and($report->stale()[0]->nameserver)->toBe('1.1.1.1')
        ->and($report->stale()[0]->values)->toBe(['198.51.100.9']);
});

it('reports Misconfigured when the authoritative answer is empty', function () use ($publicPanel): void {
    $fake = zoneWithAuthoritative([]); // no authoritative record
    foreach ($publicPanel as $ns) {
        $fake->stub('www.example.com', RecordType::A, ['93.184.216.34'], nameserver: $ns);
    }

    $report = (new PropagationChecker($fake, new AuthoritativeResolver($fake), $publicPanel))
        ->check('www.example.com', RecordType::A, 'example.com');

    expect($report->status)->toBe(PropagationStatus::Misconfigured)
        ->and($report->authoritativeValues)->toBe([]);
});

it('defaults to the six public resolvers when no panel is injected', function (): void {
    expect(PropagationChecker::DEFAULT_NAMESERVERS)->toContain('8.8.8.8', '1.1.1.1', '9.9.9.9', '208.67.222.222');
});
