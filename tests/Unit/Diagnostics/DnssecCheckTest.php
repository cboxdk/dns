<?php

declare(strict_types=1);

use Cbox\Dns\Diagnostics\Checks\DnssecCheck;
use Cbox\Dns\Diagnostics\Enums\Severity;
use Cbox\Dns\Testing\FakeResolver;
use Cbox\Dns\Tests\Support\DiagnosticFixture;

it('reports a valid chain as info', function (): void {
    // signedHierarchy() (defined in ChainWalkTest) builds an offline root->com->
    // example.com signed chain plus the validator anchored on its test root.
    [$validator, $resolver] = signedHierarchy();

    $ctx = DiagnosticFixture::context($resolver, 'example.com', dnssec: $validator);
    $finding = (new DnssecCheck)->run($ctx)[0];

    expect($finding->severity)->toBe(Severity::Info)
        ->and($finding->message)->toContain('DNSSEC is valid')
        ->and($finding->context['status'])->toBe('secure');
});

it('reports a bogus chain as an error (deny-by-default)', function (): void {
    // An empty resolver cannot satisfy the real IANA anchors, so validation is bogus.
    $finding = DiagnosticFixture::run(new DnssecCheck, new FakeResolver)[0];

    expect($finding->severity)->toBe(Severity::Error)
        ->and($finding->context['status'])->toBe('bogus');
});
