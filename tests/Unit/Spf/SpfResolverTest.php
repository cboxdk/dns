<?php

declare(strict_types=1);

use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Spf\SpfEvaluation;
use Cbox\Dns\Spf\SpfLimits;
use Cbox\Dns\Spf\SpfResolver;
use Cbox\Dns\Testing\FakeResolver;

it('flattens include: into a complete endpoint list', function (): void {
    $fake = (new FakeResolver)
        ->stub('example.com', RecordType::TXT, ['v=spf1 include:_spf.example.com ip4:192.0.2.0/24 -all'])
        ->stub('_spf.example.com', RecordType::TXT, ['v=spf1 ip4:198.51.100.0/24 ip6:2001:db8::/32 ~all']);

    $spf = (new SpfResolver($fake))->resolve('example.com');

    expect($spf->isValid())->toBeTrue()
        ->and($spf->lookups)->toBe(1)
        ->and($spf->allIp4())->toBe(['192.0.2.0/24', '198.51.100.0/24'])
        ->and($spf->allIp6())->toBe(['2001:db8::/32'])
        ->and($spf->domains())->toBe(['example.com', '_spf.example.com'])
        ->and($spf->allQualifier)->toBe('-');
});

it('expands a: and mx: mechanisms into addresses', function (): void {
    $fake = (new FakeResolver)
        ->stub('example.com', RecordType::TXT, ['v=spf1 a mx -all'])
        ->stub('example.com', RecordType::A, ['192.0.2.10'])
        ->stub('example.com', RecordType::MX, ['mail.example.com'])
        ->stub('mail.example.com', RecordType::A, ['192.0.2.20']);

    $spf = (new SpfResolver($fake))->resolve('example.com');

    expect($spf->allIp4())->toContain('192.0.2.10', '192.0.2.20')
        ->and($spf->lookups)->toBe(2); // one for a:, one for mx:
});

it('follows redirect= when there is no all', function (): void {
    $fake = (new FakeResolver)
        ->stub('example.com', RecordType::TXT, ['v=spf1 redirect=_spf.example.net'])
        ->stub('_spf.example.net', RecordType::TXT, ['v=spf1 ip4:203.0.113.0/24 -all']);

    $spf = (new SpfResolver($fake))->resolve('example.com');

    expect($spf->redirect)->not->toBeNull()
        ->and($spf->allIp4())->toBe(['203.0.113.0/24']);
});

it('detects an include loop and stops', function (): void {
    $fake = (new FakeResolver)
        ->stub('a.example', RecordType::TXT, ['v=spf1 include:b.example -all'])
        ->stub('b.example', RecordType::TXT, ['v=spf1 include:a.example -all']);

    $spf = (new SpfResolver($fake))->resolve('a.example');

    // The nested re-evaluation of a.example is refused as a loop.
    $allErrors = static function (SpfEvaluation $e) use (&$allErrors): array {
        $errors = $e->errors;

        foreach ($e->includes as $include) {
            $errors = array_merge($errors, $allErrors($include));
        }

        return $errors;
    };

    $loopFound = false;
    foreach ($allErrors($spf) as $error) {
        if (str_contains($error, 'loop')) {
            $loopFound = true;
        }
    }

    expect($loopFound)->toBeTrue();
});

it('expands a diamond include (same domain from two branches) without a false loop', function (): void {
    $fake = (new FakeResolver)
        ->stub('a.example', RecordType::TXT, ['v=spf1 include:b.example include:c.example -all'])
        ->stub('b.example', RecordType::TXT, ['v=spf1 include:d.example -all'])
        ->stub('c.example', RecordType::TXT, ['v=spf1 include:d.example -all'])
        ->stub('d.example', RecordType::TXT, ['v=spf1 ip4:192.0.2.0/24 -all']);

    $spf = (new SpfResolver($fake))->resolve('a.example');

    $errors = static function (SpfEvaluation $e) use (&$errors): array {
        $out = $e->errors;
        foreach ($e->includes as $i) {
            $out = array_merge($out, $errors($i));
        }

        return $out;
    };

    expect($errors($spf))->toBe([])                     // no spurious loop error
        ->and($spf->allIp4())->toBe(['192.0.2.0/24'])   // d's endpoints present
        ->and($spf->lookups)->toBe(4);                  // b, c, and d twice
});

it('enforces the RFC 7208 ten-lookup limit', function (): void {
    $fake = new FakeResolver;
    // A chain of 12 includes, each pointing to the next.
    for ($i = 0; $i < 12; $i++) {
        $fake->stub("d{$i}.example", RecordType::TXT, ['v=spf1 include:d'.($i + 1).'.example -all']);
    }
    $fake->stub('d12.example', RecordType::TXT, ['v=spf1 ip4:192.0.2.0/24 -all']);

    $spf = (new SpfResolver($fake))->resolve('d0.example');

    expect($spf->exceededLookupLimit)->toBeTrue()
        ->and($spf->lookups)->toBe(SpfLimits::MAX_LOOKUPS);
});

it('flags an mx resolving to more than 10 records as a permerror', function (): void {
    $fake = (new FakeResolver)
        ->stub('example.com', RecordType::TXT, ['v=spf1 mx -all'])
        ->stub('example.com', RecordType::MX, array_map(fn (int $i) => "mx{$i}.example.com", range(1, 11)));

    $spf = (new SpfResolver($fake))->resolve('example.com');

    expect($spf->errors)->toContain('mx:example.com resolves to more than 10 MX records (RFC 7208 limit)');
});

it('reports a missing SPF record', function (): void {
    $spf = (new SpfResolver(new FakeResolver))->resolve('no-spf.example');

    expect($spf->isValid())->toBeFalse()
        ->and($spf->errors)->toContain('no SPF record for no-spf.example');
});
