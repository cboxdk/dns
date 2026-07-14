<?php

declare(strict_types=1);

use Cbox\Dns\Diagnostics\Checks\DelegationCheck;
use Cbox\Dns\Diagnostics\Enums\Severity;
use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Testing\FakeResolver;
use Cbox\Dns\Tests\Support\DiagnosticFixture;

it('passes when parent and zone NS agree and glue is present', function (): void {
    $fake = (new FakeResolver)
        ->stub('example.com', RecordType::NS, ['ns1.example.com', 'ns2.example.com'])
        ->stub('ns1.example.com', RecordType::A, ['192.0.2.1'])
        ->stub('ns2.example.com', RecordType::A, ['198.51.100.2']);

    $findings = DiagnosticFixture::run(new DelegationCheck, $fake);

    expect(DiagnosticFixture::checks($findings))->toContain('delegation.match', 'delegation.glue')
        ->and(array_filter($findings, fn ($f) => $f->severity !== Severity::Info))->toBe([]);
});

it('warns when the parent delegation NS set differs from the zone NS set', function (): void {
    $fake = (new FakeResolver)
        ->stub('example.com', RecordType::NS, ['ns1.example.com', 'ns2.example.com'])
        ->stub('ns1.example.com', RecordType::A, ['192.0.2.1'])
        ->stub('ns2.example.com', RecordType::A, ['198.51.100.2'])
        // The zone, read authoritatively at ns1's IP, serves a different set.
        ->stub('example.com', RecordType::NS, ['ns1.example.com', 'ns9.example.com'], nameserver: '192.0.2.1');

    $findings = DiagnosticFixture::run(new DelegationCheck, $fake);
    $match = DiagnosticFixture::withCheck($findings, 'delegation.match');

    expect($match[0]->severity)->toBe(Severity::Warning);
});

it('warns when an in-zone nameserver has no glue', function (): void {
    $fake = (new FakeResolver)
        ->stub('example.com', RecordType::NS, ['ns1.example.com', 'ns2.example.com'])
        ->stub('ns1.example.com', RecordType::A, ['192.0.2.1']);
    // ns2.example.com has no A record — missing glue.

    $findings = DiagnosticFixture::run(new DelegationCheck, $fake);
    $glue = DiagnosticFixture::withCheck($findings, 'delegation.glue');

    expect($glue[0]->severity)->toBe(Severity::Warning)
        ->and($glue[0]->message)->toContain('ns2.example.com');
});
