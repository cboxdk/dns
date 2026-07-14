<?php

declare(strict_types=1);

use Cbox\Dns\Diagnostics\Checks\SoaCheck;
use Cbox\Dns\Diagnostics\Enums\Severity;
use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Testing\FakeResolver;
use Cbox\Dns\Tests\Support\DiagnosticFixture;

function soaZone(string $soa, ?string $soaAtNs1 = null, ?string $soaAtNs2 = null): FakeResolver
{
    $fake = (new FakeResolver)
        ->stub('example.com', RecordType::NS, ['ns1.example.com', 'ns2.example.com'])
        ->stub('ns1.example.com', RecordType::A, ['192.0.2.1'])
        ->stub('ns2.example.com', RecordType::A, ['198.51.100.2'])
        ->stub('example.com', RecordType::SOA, [$soa]);

    if ($soaAtNs1 !== null) {
        $fake->stub('example.com', RecordType::SOA, [$soaAtNs1], nameserver: '192.0.2.1');
    }

    if ($soaAtNs2 !== null) {
        $fake->stub('example.com', RecordType::SOA, [$soaAtNs2], nameserver: '198.51.100.2');
    }

    return $fake;
}

it('passes for a well-formed SOA with sane timers and agreeing serials', function (): void {
    $fake = soaZone('ns1.example.com hostmaster.example.com 2024010101 7200 3600 1209600 3600');

    $findings = DiagnosticFixture::run(new SoaCheck, $fake);

    expect(array_filter($findings, fn ($f) => $f->severity !== Severity::Info))->toBe([])
        ->and(DiagnosticFixture::checks($findings))->toContain('soa.mname', 'soa.timers', 'soa.serial');
});

it('errors when no nameserver returns a SOA', function (): void {
    $fake = (new FakeResolver)
        ->stub('example.com', RecordType::NS, ['ns1.example.com'])
        ->stub('ns1.example.com', RecordType::A, ['192.0.2.1']);

    $findings = DiagnosticFixture::run(new SoaCheck, $fake);

    expect(DiagnosticFixture::withCheck($findings, 'soa.presence')[0]->severity)->toBe(Severity::Error);
});

it('warns when MNAME is not one of the zone nameservers', function (): void {
    $fake = soaZone('primary.otherdns.net hostmaster.example.com 2024010101 7200 3600 1209600 3600');

    $mname = DiagnosticFixture::withCheck(DiagnosticFixture::run(new SoaCheck, $fake), 'soa.mname');

    expect($mname[0]->severity)->toBe(Severity::Warning);
});

it('warns on insane timers (retry not less than refresh)', function (): void {
    // retry (7200) >= refresh (3600) is invalid.
    $fake = soaZone('ns1.example.com hostmaster.example.com 2024010101 3600 7200 1209600 3600');

    $timers = DiagnosticFixture::withCheck(DiagnosticFixture::run(new SoaCheck, $fake), 'soa.timers');

    expect($timers[0]->severity)->toBe(Severity::Warning);
});

it('warns when authoritative nameservers disagree on the serial', function (): void {
    $fake = soaZone(
        'ns1.example.com hostmaster.example.com 100 7200 3600 1209600 3600',
        soaAtNs1: 'ns1.example.com hostmaster.example.com 100 7200 3600 1209600 3600',
        soaAtNs2: 'ns1.example.com hostmaster.example.com 200 7200 3600 1209600 3600',
    );

    $serial = DiagnosticFixture::withCheck(DiagnosticFixture::run(new SoaCheck, $fake), 'soa.serial');

    expect($serial[0]->severity)->toBe(Severity::Warning);
});
