<?php

declare(strict_types=1);

use Cbox\Dns\Diagnostics\Checks\DmarcCheck;
use Cbox\Dns\Diagnostics\Enums\Severity;
use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Testing\FakeResolver;
use Cbox\Dns\Tests\Support\DiagnosticFixture;

it('passes for an enforced DMARC policy', function (): void {
    $fake = (new FakeResolver)->stub('_dmarc.example.com', RecordType::TXT, [
        'v=DMARC1; p=reject; rua=mailto:dmarc@example.com',
    ]);

    $policy = DiagnosticFixture::withCheck(DiagnosticFixture::run(new DmarcCheck, $fake), 'dmarc.policy');

    expect($policy[0]->severity)->toBe(Severity::Info)
        ->and($policy[0]->context['policy'])->toBe('reject');
});

it('warns when DMARC is absent', function (): void {
    expect(DiagnosticFixture::run(new DmarcCheck, new FakeResolver)[0]->check)->toBe('dmarc.presence')
        ->and(DiagnosticFixture::run(new DmarcCheck, new FakeResolver)[0]->severity)->toBe(Severity::Warning);
});

it('warns that p=none is monitor-only', function (): void {
    $fake = (new FakeResolver)->stub('_dmarc.example.com', RecordType::TXT, ['v=DMARC1; p=none']);

    $policy = DiagnosticFixture::withCheck(DiagnosticFixture::run(new DmarcCheck, $fake), 'dmarc.policy');

    expect($policy[0]->severity)->toBe(Severity::Warning)
        ->and($policy[0]->message)->toContain('p=none');
});

it('warns when the p= policy is missing or invalid', function (): void {
    $fake = (new FakeResolver)->stub('_dmarc.example.com', RecordType::TXT, ['v=DMARC1; sp=reject']);

    $policy = DiagnosticFixture::withCheck(DiagnosticFixture::run(new DmarcCheck, $fake), 'dmarc.policy');

    expect($policy[0]->severity)->toBe(Severity::Warning);
});
