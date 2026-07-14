<?php

declare(strict_types=1);

use Cbox\Dns\Enums\Rcode;
use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Resolution\CnameResolver;
use Cbox\Dns\Testing\FakeResolver;
use Cbox\Dns\ValueObjects\DnsRecord;
use Cbox\Dns\ValueObjects\DnsResponse;

it('follows a CNAME chain a recursive resolver already flattened', function (): void {
    // One response carries the CNAME and the final A (the recursive case).
    $flattened = new DnsResponse(RecordType::A, 'www.example.com', [
        new DnsRecord(RecordType::A, 'web.example.com', '93.184.216.34'),
    ], null, false, false, answer: [
        new DnsRecord(RecordType::CNAME, 'www.example.com', 'web.example.com'),
        new DnsRecord(RecordType::A, 'web.example.com', '93.184.216.34'),
    ]);

    $fake = (new FakeResolver)->stubResponse('www.example.com', RecordType::A, $flattened);

    $chain = (new CnameResolver($fake))->resolve('www.example.com', RecordType::A);

    expect($chain->completed)->toBeTrue()
        ->and($chain->aliases())->toBe(['www.example.com', 'web.example.com'])
        ->and($chain->canonicalName())->toBe('web.example.com')
        ->and($chain->values())->toBe(['93.184.216.34']);
});

it('chases the CNAME target when the answering server did not flatten it', function (): void {
    $cnameOnly = new DnsResponse(RecordType::A, 'www.example.com', [], null, false, false, answer: [
        new DnsRecord(RecordType::CNAME, 'www.example.com', 'web.example.net'),
    ]);
    $finalA = new DnsResponse(RecordType::A, 'web.example.net', [
        new DnsRecord(RecordType::A, 'web.example.net', '203.0.113.5'),
    ]);

    $fake = (new FakeResolver)
        ->stubResponse('www.example.com', RecordType::A, $cnameOnly)
        ->stubResponse('web.example.net', RecordType::A, $finalA);

    $chain = (new CnameResolver($fake))->resolve('www.example.com', RecordType::A);

    expect($chain->completed)->toBeTrue()
        ->and($chain->canonicalName())->toBe('web.example.net')
        ->and($chain->values())->toBe(['203.0.113.5']);
});

it('stops on a CNAME loop instead of spinning', function (): void {
    $aToB = new DnsResponse(RecordType::A, 'a.example.com', [], null, false, false, answer: [
        new DnsRecord(RecordType::CNAME, 'a.example.com', 'b.example.com'),
    ]);
    $bToA = new DnsResponse(RecordType::A, 'b.example.com', [], null, false, false, answer: [
        new DnsRecord(RecordType::CNAME, 'b.example.com', 'a.example.com'),
    ]);

    $fake = (new FakeResolver)
        ->stubResponse('a.example.com', RecordType::A, $aToB)
        ->stubResponse('b.example.com', RecordType::A, $bToA);

    $chain = (new CnameResolver($fake))->resolve('a.example.com', RecordType::A);

    expect($chain->completed)->toBeFalse()
        ->and($chain->stoppedReason)->toContain('loop');
});

it('stops on an oscillating chain where a later response points back to an intermediate', function (): void {
    // response 1 flattens a -> b -> c; response 2 (c) points back to intermediate b.
    $flat = new DnsResponse(RecordType::A, 'a.example.com', [], null, false, false, answer: [
        new DnsRecord(RecordType::CNAME, 'a.example.com', 'b.example.com'),
        new DnsRecord(RecordType::CNAME, 'b.example.com', 'c.example.com'),
    ]);
    $back = new DnsResponse(RecordType::A, 'c.example.com', [], null, false, false, answer: [
        new DnsRecord(RecordType::CNAME, 'c.example.com', 'b.example.com'),
    ]);

    $fake = (new FakeResolver)
        ->stubResponse('a.example.com', RecordType::A, $flat)
        ->stubResponse('c.example.com', RecordType::A, $back);

    $chain = (new CnameResolver($fake))->resolve('a.example.com', RecordType::A);

    // b was consumed as an intermediate, so pointing back to it is caught as a loop
    // (not left to run out MAX_DEPTH).
    expect($chain->completed)->toBeFalse()
        ->and($chain->stoppedReason)->toContain('loop');
});

it('reports NXDOMAIN without an answer', function (): void {
    $fake = (new FakeResolver)->stubFailure('nope.example.com', RecordType::A, Rcode::NxDomain);

    $chain = (new CnameResolver($fake))->resolve('nope.example.com', RecordType::A);

    expect($chain->completed)->toBeFalse()
        ->and($chain->stoppedReason)->toContain('NXDOMAIN');
});
