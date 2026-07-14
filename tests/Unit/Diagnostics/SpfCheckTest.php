<?php

declare(strict_types=1);

use Cbox\Dns\Diagnostics\Checks\SpfCheck;
use Cbox\Dns\Diagnostics\Enums\Severity;
use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Testing\FakeResolver;
use Cbox\Dns\Tests\Support\DiagnosticFixture;

it('passes for a single valid SPF record within the lookup budget', function (): void {
    $fake = (new FakeResolver)->stub('example.com', RecordType::TXT, [
        'v=spf1 include:_spf.example.com mx ~all',
    ]);

    $findings = DiagnosticFixture::run(new SpfCheck, $fake);

    expect($findings[0]->severity)->toBe(Severity::Info)
        ->and($findings[0]->check)->toBe('spf.presence');
});

it('warns when there is no SPF record', function (): void {
    $fake = (new FakeResolver)->stub('example.com', RecordType::TXT, ['some-unrelated-verification=abc']);

    expect(DiagnosticFixture::run(new SpfCheck, $fake)[0]->severity)->toBe(Severity::Warning);
});

it('warns when multiple SPF records are published', function (): void {
    $fake = (new FakeResolver)->stub('example.com', RecordType::TXT, [
        'v=spf1 include:a.example.com ~all',
        'v=spf1 include:b.example.com ~all',
    ]);

    $presence = DiagnosticFixture::withCheck(DiagnosticFixture::run(new SpfCheck, $fake), 'spf.presence');

    expect($presence[0]->severity)->toBe(Severity::Warning)
        ->and($presence[0]->message)->toContain('Multiple');
});

it('errors when the DNS-lookup mechanism budget is exceeded', function (): void {
    $mechanisms = implode(' ', array_map(static fn (int $i): string => "include:i{$i}.example.com", range(1, 11)));
    $fake = (new FakeResolver)->stub('example.com', RecordType::TXT, ["v=spf1 {$mechanisms} ~all"]);

    $lookups = DiagnosticFixture::withCheck(DiagnosticFixture::run(new SpfCheck, $fake), 'spf.lookups');

    expect($lookups[0]->severity)->toBe(Severity::Error)
        ->and($lookups[0]->context['lookups'])->toBe(11);
});

it('warns on a permissive +all', function (): void {
    $fake = (new FakeResolver)->stub('example.com', RecordType::TXT, ['v=spf1 include:_spf.example.com +all']);

    $all = DiagnosticFixture::withCheck(DiagnosticFixture::run(new SpfCheck, $fake), 'spf.all');

    expect($all[0]->severity)->toBe(Severity::Warning);
});
