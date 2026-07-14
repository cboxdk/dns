<?php

declare(strict_types=1);

use Cbox\Dns\Diagnostics\Enums\Severity;
use Cbox\Dns\Diagnostics\Finding;
use Cbox\Dns\Diagnostics\Report;

it('reports errors and a failed grade when an error finding is present', function (): void {
    $report = new Report([
        Finding::info('SOA', 'soa.timers', 'ok'),
        Finding::error('Nameservers', 'ns.lame', 'lame server'),
    ]);

    expect($report->hasErrors())->toBeTrue()
        ->and($report->passed())->toBeFalse();
});

it('does not pass with only warnings, but reports no errors', function (): void {
    $report = new Report([
        Finding::info('CAA', 'caa.presence', 'ok'),
        Finding::warning('Email', 'spf.presence', 'no SPF'),
    ]);

    expect($report->hasErrors())->toBeFalse()
        ->and($report->passed())->toBeFalse();
});

it('passes with only info findings', function (): void {
    $report = new Report([
        Finding::info('CAA', 'caa.presence', 'ok'),
        Finding::info('DNSSEC', 'dnssec.chain', 'secure'),
    ]);

    expect($report->passed())->toBeTrue()
        ->and($report->hasErrors())->toBeFalse();
});

it('groups findings by severity and by category', function (): void {
    $report = new Report([
        Finding::error('Nameservers', 'ns.lame', 'lame'),
        Finding::warning('Email', 'spf.presence', 'no SPF'),
        Finding::info('Email', 'mx.redundancy', '2 MX'),
    ]);

    $bySeverity = $report->bySeverity();
    expect($bySeverity[Severity::Error->value])->toHaveCount(1)
        ->and($bySeverity[Severity::Warning->value])->toHaveCount(1)
        ->and($bySeverity[Severity::Info->value])->toHaveCount(1);

    $byCategory = $report->byCategory();
    expect($byCategory)->toHaveKeys(['Nameservers', 'Email'])
        ->and($byCategory['Email'])->toHaveCount(2);
});
