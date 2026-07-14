<?php

declare(strict_types=1);

use Cbox\Dns\Diagnostics\Checks\MxCheck;
use Cbox\Dns\Diagnostics\Enums\Severity;
use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Testing\FakeResolver;
use Cbox\Dns\Tests\Support\DiagnosticFixture;

it('passes for two resolvable public MX hosts with forward-confirmed reverse DNS', function (): void {
    $fake = (new FakeResolver)
        ->stub('example.com', RecordType::MX, ['mx1.example.com', 'mx2.example.com'])
        ->stub('mx1.example.com', RecordType::A, ['192.0.2.10'])
        ->stub('mx2.example.com', RecordType::A, ['198.51.100.20'])
        ->stub('10.2.0.192.in-addr.arpa', RecordType::PTR, ['mx1.example.com'])
        ->stub('20.100.51.198.in-addr.arpa', RecordType::PTR, ['mx2.example.com']);

    $findings = DiagnosticFixture::run(new MxCheck, $fake);

    expect(array_filter($findings, fn ($f) => $f->severity !== Severity::Info))->toBe([])
        ->and(DiagnosticFixture::checks($findings))->toContain('mx.redundancy', 'mx.fcrdns');
});

it('warns when no MX record is published', function (): void {
    $findings = DiagnosticFixture::run(new MxCheck, new FakeResolver);

    expect(DiagnosticFixture::withCheck($findings, 'mx.presence')[0]->severity)->toBe(Severity::Warning);
});

it('treats a null MX (.) as an explicit no-mail declaration', function (): void {
    $fake = (new FakeResolver)->stub('example.com', RecordType::MX, ['.']);

    $presence = DiagnosticFixture::withCheck(DiagnosticFixture::run(new MxCheck, $fake), 'mx.presence');

    expect($presence[0]->severity)->toBe(Severity::Info);
});

it('warns on a single MX host (no redundancy)', function (): void {
    $fake = (new FakeResolver)
        ->stub('example.com', RecordType::MX, ['mx1.example.com'])
        ->stub('mx1.example.com', RecordType::A, ['192.0.2.10'])
        ->stub('10.2.0.192.in-addr.arpa', RecordType::PTR, ['mx1.example.com']);

    $redundancy = DiagnosticFixture::withCheck(DiagnosticFixture::run(new MxCheck, $fake), 'mx.redundancy');

    expect($redundancy[0]->severity)->toBe(Severity::Warning);
});

it('errors when the MX target is an IP literal', function (): void {
    $fake = (new FakeResolver)->stub('example.com', RecordType::MX, ['192.0.2.10']);

    $target = DiagnosticFixture::withCheck(DiagnosticFixture::run(new MxCheck, $fake), 'mx.target');

    expect($target[0]->severity)->toBe(Severity::Error)
        ->and($target[0]->message)->toContain('IP literal');
});

it('errors when the MX target is a CNAME', function (): void {
    $fake = (new FakeResolver)
        ->stub('example.com', RecordType::MX, ['mail.example.com', 'mx2.example.com'])
        ->stub('mail.example.com', RecordType::CNAME, ['store.example.net']);

    $target = DiagnosticFixture::withCheck(DiagnosticFixture::run(new MxCheck, $fake), 'mx.target');

    expect($target[0]->severity)->toBe(Severity::Error)
        ->and($target[0]->message)->toContain('CNAME');
});

it('errors when the MX target does not resolve', function (): void {
    $fake = (new FakeResolver)
        ->stub('example.com', RecordType::MX, ['mx1.example.com', 'mx2.example.com']);

    $target = DiagnosticFixture::withCheck(DiagnosticFixture::run(new MxCheck, $fake), 'mx.target');

    expect($target[0]->severity)->toBe(Severity::Error)
        ->and($target[0]->message)->toContain('does not resolve');
});

it('errors when the MX target resolves only to a private address', function (): void {
    $fake = (new FakeResolver)
        ->stub('example.com', RecordType::MX, ['mx1.example.com', 'mx2.example.com'])
        ->stub('mx1.example.com', RecordType::A, ['10.0.0.5'])
        ->stub('mx2.example.com', RecordType::A, ['198.51.100.20'])
        ->stub('20.100.51.198.in-addr.arpa', RecordType::PTR, ['mx2.example.com']);

    $target = DiagnosticFixture::withCheck(DiagnosticFixture::run(new MxCheck, $fake), 'mx.target');

    expect($target[0]->severity)->toBe(Severity::Error)
        ->and($target[0]->message)->toContain('private');
});

it('warns when an MX address has no PTR record', function (): void {
    $fake = (new FakeResolver)
        ->stub('example.com', RecordType::MX, ['mx1.example.com', 'mx2.example.com'])
        ->stub('mx1.example.com', RecordType::A, ['192.0.2.10'])
        ->stub('mx2.example.com', RecordType::A, ['198.51.100.20'])
        ->stub('20.100.51.198.in-addr.arpa', RecordType::PTR, ['mx2.example.com']);
    // mx1's address 192.0.2.10 has no PTR.

    $ptr = DiagnosticFixture::withCheck(DiagnosticFixture::run(new MxCheck, $fake), 'mx.ptr');

    expect($ptr)->not->toBe([])
        ->and($ptr[0]->severity)->toBe(Severity::Warning);
});

it('warns when an MX address is not forward-confirmed (FCrDNS)', function (): void {
    $fake = (new FakeResolver)
        ->stub('example.com', RecordType::MX, ['mx1.example.com', 'mx2.example.com'])
        ->stub('mx1.example.com', RecordType::A, ['192.0.2.10'])
        ->stub('mx2.example.com', RecordType::A, ['198.51.100.20'])
        // PTR points at a name that does NOT resolve back to 192.0.2.10.
        ->stub('10.2.0.192.in-addr.arpa', RecordType::PTR, ['stranger.example.net'])
        ->stub('stranger.example.net', RecordType::A, ['203.0.113.7'])
        ->stub('20.100.51.198.in-addr.arpa', RecordType::PTR, ['mx2.example.com']);

    $fcrdns = DiagnosticFixture::withCheck(DiagnosticFixture::run(new MxCheck, $fake), 'mx.fcrdns');
    $warnings = array_filter($fcrdns, fn ($f) => $f->severity === Severity::Warning);

    expect($warnings)->not->toBe([]);
});
