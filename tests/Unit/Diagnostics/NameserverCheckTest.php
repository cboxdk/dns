<?php

declare(strict_types=1);

use Cbox\Dns\Diagnostics\Checks\NameserverCheck;
use Cbox\Dns\Diagnostics\Enums\Severity;
use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Testing\FakeResolver;
use Cbox\Dns\Tests\Support\DiagnosticFixture;

const SANE_SOA = 'ns1.example.com hostmaster.example.com 2024010101 7200 3600 1209600 3600';

function healthyNsZone(): FakeResolver
{
    return (new FakeResolver)
        ->stub('example.com', RecordType::NS, ['ns1.example.com', 'ns2.example.com'])
        ->stub('ns1.example.com', RecordType::A, ['192.0.2.1'])
        ->stub('ns2.example.com', RecordType::A, ['198.51.100.2'])
        ->stub('example.com', RecordType::SOA, [SANE_SOA]);
}

it('passes for two public, authoritative, non-recursive nameservers', function (): void {
    $findings = DiagnosticFixture::run(new NameserverCheck, healthyNsZone());

    expect(array_filter($findings, fn ($f) => $f->severity !== Severity::Info))->toBe([])
        ->and(DiagnosticFixture::checks($findings))->toContain('ns.count', 'ns.authoritative');
});

it('warns when fewer than two nameservers are delegated', function (): void {
    $fake = (new FakeResolver)
        ->stub('example.com', RecordType::NS, ['ns1.example.com'])
        ->stub('ns1.example.com', RecordType::A, ['192.0.2.1'])
        ->stub('example.com', RecordType::SOA, [SANE_SOA]);

    $count = DiagnosticFixture::withCheck(DiagnosticFixture::run(new NameserverCheck, $fake), 'ns.count');

    expect($count[0]->severity)->toBe(Severity::Warning);
});

it('errors when a nameserver is a CNAME', function (): void {
    $fake = healthyNsZone()
        ->stub('ns2.example.com', RecordType::CNAME, ['real-ns.example.net']);

    $cname = DiagnosticFixture::withCheck(DiagnosticFixture::run(new NameserverCheck, $fake), 'ns.cname');

    expect($cname[0]->severity)->toBe(Severity::Error);
});

it('errors when a nameserver resolves to a private RFC1918 address', function (): void {
    $fake = (new FakeResolver)
        ->stub('example.com', RecordType::NS, ['ns1.example.com', 'ns2.example.com'])
        ->stub('ns1.example.com', RecordType::A, ['192.0.2.1'])
        ->stub('ns2.example.com', RecordType::A, ['10.0.0.5'])
        ->stub('example.com', RecordType::SOA, [SANE_SOA]);

    $private = DiagnosticFixture::withCheck(DiagnosticFixture::run(new NameserverCheck, $fake), 'ns.private-ip');

    expect($private[0]->severity)->toBe(Severity::Error)
        ->and($private[0]->message)->toContain('10.0.0.5');
});

it('errors when a nameserver answers but not authoritatively (lame)', function (): void {
    $fake = (new FakeResolver)
        ->stub('example.com', RecordType::NS, ['ns1.example.com', 'ns2.example.com'])
        ->stub('ns1.example.com', RecordType::A, ['192.0.2.1'])
        ->stub('ns2.example.com', RecordType::A, ['198.51.100.2'])
        // A SOA answer that is NOT authoritative for the zone = lame.
        ->stub('example.com', RecordType::SOA, [SANE_SOA], authoritative: false);

    $lame = DiagnosticFixture::withCheck(DiagnosticFixture::run(new NameserverCheck, $fake), 'ns.lame');

    expect($lame)->not->toBe([])
        ->and($lame[0]->severity)->toBe(Severity::Error);
});

it('warns when a nameserver does not answer with a SOA', function (): void {
    $fake = (new FakeResolver)
        ->stub('example.com', RecordType::NS, ['ns1.example.com', 'ns2.example.com'])
        ->stub('ns1.example.com', RecordType::A, ['192.0.2.1'])
        ->stub('ns2.example.com', RecordType::A, ['198.51.100.2']);
    // No SOA stub at all — the servers do not answer for the zone.

    $respond = DiagnosticFixture::withCheck(DiagnosticFixture::run(new NameserverCheck, $fake), 'ns.respond');

    expect($respond)->not->toBe([])
        ->and($respond[0]->severity)->toBe(Severity::Warning);
});

it('warns when a nameserver offers open recursion for a foreign name', function (): void {
    $fake = healthyNsZone()
        ->stub('recursion-probe.cbox-diagnostics.example', RecordType::A, ['203.0.113.9'], nameserver: '192.0.2.1');

    $recursion = DiagnosticFixture::withCheck(DiagnosticFixture::run(new NameserverCheck, $fake), 'ns.recursion');

    expect($recursion)->not->toBe([])
        ->and($recursion[0]->severity)->toBe(Severity::Warning);
});
