<?php

declare(strict_types=1);

use Cbox\Dns\Diagnostics\Checks\DkimCheck;
use Cbox\Dns\Diagnostics\Enums\Severity;
use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Testing\FakeResolver;
use Cbox\Dns\Tests\Support\DiagnosticFixture;

it('reports a published DKIM key for the given selector as info', function (): void {
    $fake = (new FakeResolver)->stub('s1._domainkey.example.com', RecordType::TXT, [
        'v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ',
    ]);

    $finding = DiagnosticFixture::run(new DkimCheck('s1'), $fake)[0];

    expect($finding->severity)->toBe(Severity::Info)
        ->and($finding->check)->toBe('dkim.presence');
});

it('warns when no DKIM key exists for the selector', function (): void {
    $finding = DiagnosticFixture::run(new DkimCheck('missing'), new FakeResolver)[0];

    expect($finding->severity)->toBe(Severity::Warning)
        ->and($finding->message)->toContain('missing');
});

it('warns when the DKIM key is revoked (empty p=)', function (): void {
    $fake = (new FakeResolver)->stub('s1._domainkey.example.com', RecordType::TXT, ['v=DKIM1; k=rsa; p=']);

    $finding = DiagnosticFixture::run(new DkimCheck('s1'), $fake)[0];

    expect($finding->severity)->toBe(Severity::Warning)
        ->and($finding->check)->toBe('dkim.revoked');
});
