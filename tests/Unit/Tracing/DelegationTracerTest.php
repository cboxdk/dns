<?php

declare(strict_types=1);

use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Testing\FakeResolver;
use Cbox\Dns\Tracing\DelegationTracer;
use Cbox\Dns\Tracing\RootHints;
use Cbox\Dns\ValueObjects\DnsRecord;
use Cbox\Dns\ValueObjects\DnsResponse;

function referral(string $childZone, string $nsName, string $glueIp): DnsResponse
{
    return new DnsResponse(
        RecordType::NS,
        'example.com',
        [], // no ANSWER of the queried type — it is a referral
        null,
        authoritative: false,
        authority: [new DnsRecord(RecordType::NS, $childZone, $nsName, 172800)],
        additional: [new DnsRecord(RecordType::A, $nsName, $glueIp, 172800)],
    );
}

function authoritativeAnswer(string $zone, string $nsName): DnsResponse
{
    return new DnsResponse(
        RecordType::NS,
        $zone,
        [new DnsRecord(RecordType::NS, $zone, $nsName, 3600)],
        null,
        authoritative: true,
    );
}

it('traces a full root → TLD → domain delegation', function (): void {
    $rootIp = RootHints::ipv4()['a.root-servers.net'];

    $fake = (new FakeResolver)
        // Every root server we might hit refers down to com.
        ->stubResponse('example.com', RecordType::NS, referral('com', 'a.gtld-servers.net', '192.5.6.30'), nameserver: $rootIp)
        // The com server refers down to example.com.
        ->stubResponse('example.com', RecordType::NS, referral('example.com', 'ns1.example.com', '93.184.216.34'), nameserver: '192.5.6.30')
        // example.com's server answers authoritatively.
        ->stubResponse('example.com', RecordType::NS, authoritativeAnswer('example.com', 'ns1.example.com'), nameserver: '93.184.216.34');

    $trace = (new DelegationTracer($fake))->trace('example.com');

    expect($trace->completed)->toBeTrue()
        ->and($trace->path())->toBe(['.', 'com', 'example.com'])
        ->and($trace->answer)->toHaveCount(1)
        ->and($trace->hops[1]->childZone)->toBe('example.com')
        ->and($trace->hops[1]->glue)->toBe(['ns1.example.com' => '93.184.216.34']);
});

it('stops on a self-referential (looping) delegation instead of spinning', function (): void {
    $rootIp = RootHints::ipv4()['a.root-servers.net'];

    $fake = (new FakeResolver)
        ->stubResponse('example.com', RecordType::NS, referral('com', 'a.gtld-servers.net', '192.5.6.30'), nameserver: $rootIp)
        // The com server refers back to com — no downward progress.
        ->stubResponse('example.com', RecordType::NS, referral('com', 'a.gtld-servers.net', '192.5.6.30'), nameserver: '192.5.6.30');

    $trace = (new DelegationTracer($fake))->trace('example.com');

    expect($trace->completed)->toBeFalse()
        ->and($trace->stoppedReason)->toContain('does not descend')
        ->and(count($trace->hops))->toBeLessThan(DelegationTracer::MAX_HOPS);
});

it('stops with a reason when no nameserver answers', function (): void {
    // Strict fake with no stubs → every root query throws → the trace dead-ends.
    $trace = (new DelegationTracer((new FakeResolver)->strict()))->trace('example.com');

    expect($trace->completed)->toBeFalse()
        ->and($trace->hops)->toHaveCount(1)
        ->and($trace->hops[0]->answered)->toBeFalse()
        ->and($trace->stoppedReason)->toContain('answered');
});

it('ignores foreign NS records a hostile parent splices into the referral', function (): void {
    $rootIp = RootHints::ipv4()['a.root-servers.net'];

    // The referral for com also carries an unrelated NS RRset for evil.tld with glue.
    $poisoned = new DnsResponse(
        RecordType::NS,
        'example.com',
        [],
        null,
        authoritative: false,
        authority: [
            new DnsRecord(RecordType::NS, 'com', 'a.gtld-servers.net', 172800),
            new DnsRecord(RecordType::NS, 'evil.tld', 'ns.attacker.example', 172800),
        ],
        additional: [
            new DnsRecord(RecordType::A, 'a.gtld-servers.net', '192.5.6.30', 172800),
            new DnsRecord(RecordType::A, 'ns.attacker.example', '203.0.113.66', 172800),
        ],
    );

    $fake = (new FakeResolver)
        ->stubResponse('example.com', RecordType::NS, $poisoned, nameserver: $rootIp)
        ->stubResponse('example.com', RecordType::NS, authoritativeAnswer('example.com', 'ns1.example.com'), nameserver: '192.5.6.30');

    $trace = (new DelegationTracer($fake))->trace('example.com');

    $queriedServers = array_map(fn ($q) => $q->nameserver, $fake->queries());

    // Only com's own nameserver was followed; the attacker glue never entered the chain.
    expect($trace->hops[0]->referralNameservers)->toBe(['a.gtld-servers.net'])
        ->and($trace->hops[0]->glue)->toBe(['a.gtld-servers.net' => '192.5.6.30'])
        ->and($queriedServers)->not->toContain('203.0.113.66')
        ->and($trace->completed)->toBeTrue();
});

it('builds the reverse pointer name for an IP trace', function (): void {
    $fake = new FakeResolver;
    $trace = (new DelegationTracer($fake))->traceReverse('8.8.8.8');

    expect($trace->name)->toBe('8.8.8.8.in-addr.arpa')
        ->and($trace->type)->toBe(RecordType::PTR);
});

it('reports a non-IP reverse trace without querying', function (): void {
    $trace = (new DelegationTracer(new FakeResolver))->traceReverse('not-an-ip');

    expect($trace->completed)->toBeFalse()
        ->and($trace->stoppedReason)->toContain('not an IP');
});
