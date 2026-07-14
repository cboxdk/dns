<?php

declare(strict_types=1);

use Cbox\Dns\Diagnostics\Checks\CaaCheck;
use Cbox\Dns\Diagnostics\Enums\Severity;
use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Testing\FakeResolver;
use Cbox\Dns\Tests\Support\DiagnosticFixture;

it('reports presence of CAA as info', function (): void {
    $fake = (new FakeResolver)->stub('example.com', RecordType::CAA, ['0 issue "letsencrypt.org"']);

    $finding = DiagnosticFixture::run(new CaaCheck, $fake)[0];

    expect($finding->severity)->toBe(Severity::Info)
        ->and($finding->message)->toContain('CAA is present')
        ->and($finding->context['records'])->toBe(['0 issue "letsencrypt.org"']);
});

it('reports absence of CAA as info (not a fault)', function (): void {
    $finding = DiagnosticFixture::run(new CaaCheck, new FakeResolver)[0];

    expect($finding->severity)->toBe(Severity::Info)
        ->and($finding->message)->toContain('No CAA');
});
