<?php

declare(strict_types=1);

use Cbox\Dns\Diagnostics\Checks\PropagationCheck;
use Cbox\Dns\Diagnostics\Enums\Severity;
use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Testing\FakeResolver;
use Cbox\Dns\Tests\Support\DiagnosticFixture;

function propagationZone(): FakeResolver
{
    return (new FakeResolver)
        ->stub('example.com', RecordType::NS, ['ns1.example.com'])
        ->stub('ns1.example.com', RecordType::A, ['192.0.2.1']);
}

it('reports full propagation as info', function (): void {
    $fake = propagationZone()
        ->stub('example.com', RecordType::A, ['93.184.216.34'], nameserver: '192.0.2.1') // authoritative
        ->stub('example.com', RecordType::A, ['93.184.216.34']);                          // recursive panel

    $finding = (new PropagationCheck)->run(DiagnosticFixture::context($fake))[0];

    expect($finding->severity)->toBe(Severity::Info)
        ->and($finding->context['status'])->toBe('propagated');
});

it('warns while the record is still propagating', function (): void {
    $fake = propagationZone()
        ->stub('example.com', RecordType::A, ['93.184.216.34'], nameserver: '192.0.2.1') // authoritative (new)
        ->stub('example.com', RecordType::A, ['198.51.100.9']);                           // recursive (stale)

    $finding = (new PropagationCheck)->run(DiagnosticFixture::context($fake))[0];

    expect($finding->severity)->toBe(Severity::Warning)
        ->and($finding->context['status'])->toBe('pending');
});

it('warns when there is no authoritative apex A to propagate', function (): void {
    $finding = (new PropagationCheck)->run(DiagnosticFixture::context(propagationZone()))[0];

    expect($finding->severity)->toBe(Severity::Warning)
        ->and($finding->context['status'])->toBe('misconfigured');
});
