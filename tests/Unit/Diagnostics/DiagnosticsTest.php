<?php

declare(strict_types=1);

use Cbox\Dns\Diagnostics\Checks\DkimCheck;
use Cbox\Dns\Diagnostics\Contracts\Check;
use Cbox\Dns\Diagnostics\DiagnosticContext;
use Cbox\Dns\Diagnostics\Diagnostics;
use Cbox\Dns\Diagnostics\Report;
use Cbox\Dns\Dns;
use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Testing\FakeResolver;

/**
 * A zone that is broken in several independent ways: a single private-IP nameserver,
 * no SOA, no mail, no SPF/DMARC — so the run produces errors and warnings across
 * multiple categories.
 */
function brokenZone(): FakeResolver
{
    return (new FakeResolver)
        ->stub('example.com', RecordType::NS, ['ns1.example.com'])
        ->stub('ns1.example.com', RecordType::A, ['10.0.0.5']);
}

it('aggregates findings across every default check and flags errors', function (): void {
    $report = (new Diagnostics(brokenZone()))->run('example.com');

    expect($report)->toBeInstanceOf(Report::class)
        ->and($report->hasErrors())->toBeTrue()
        ->and($report->passed())->toBeFalse();

    // Errors surfaced from independent checks.
    $errorChecks = array_map(
        static fn ($f) => $f->check,
        $report->bySeverity()['error'],
    );
    expect($errorChecks)->toContain('ns.private-ip', 'soa.presence', 'dnssec.chain');

    // Findings span multiple categories.
    expect(array_keys($report->byCategory()))
        ->toContain('Nameservers', 'SOA', 'Email', 'DNSSEC', 'Propagation');
});

it('runs the nine-check default catalog', function (): void {
    expect(Diagnostics::defaultChecks())->toHaveCount(9)
        ->and(Diagnostics::defaultChecks())->each->toBeInstanceOf(Check::class);
});

it('runs only the checks passed to runWith (e.g. selector-scoped DKIM)', function (): void {
    $report = (new Diagnostics(new FakeResolver))->runWith('example.com', [new DkimCheck('sel')]);

    expect($report->findings)->toHaveCount(1)
        ->and($report->findings[0]->category)->toBe('Email')
        ->and($report->findings[0]->check)->toBe('dkim.presence');
});

it('records a check that throws as an error instead of aborting the run', function (): void {
    $exploding = new class implements Check
    {
        public function run(DiagnosticContext $ctx): array
        {
            throw new RuntimeException('boom');
        }
    };

    $report = (new Diagnostics(new FakeResolver))->runWith('example.com', [$exploding]);

    expect($report->hasErrors())->toBeTrue()
        ->and($report->findings[0]->check)->toBe('check.failed')
        ->and($report->findings[0]->message)->toContain('boom');
});

it('is reachable through the Dns facade', function (): void {
    $report = (new Dns(brokenZone()))->diagnose('example.com');

    expect($report)->toBeInstanceOf(Report::class)
        ->and($report->hasErrors())->toBeTrue();
});
