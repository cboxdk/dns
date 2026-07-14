<?php

declare(strict_types=1);

use Cbox\Dns\Enums\Rcode;
use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Exceptions\ResolutionFailed;
use Cbox\Dns\Testing\FakeResolver;
use Cbox\Dns\ValueObjects\DnsRecord;
use Cbox\Dns\ValueObjects\QueryRequest;

it('stubs values with a custom TTL and priority', function (): void {
    $record = (new FakeResolver)
        ->stub('example.com', RecordType::MX, ['mail.example.com'], ttl: 60, priority: 10)
        ->query('example.com', RecordType::MX)
        ->records[0];

    expect($record->ttl)->toBe(60)->and($record->priority)->toBe(10);
});

it('stubs fully-formed records for per-record control', function (): void {
    $records = [
        new DnsRecord(RecordType::MX, 'example.com', 'mx1.example.com', 300, priority: 10),
        new DnsRecord(RecordType::MX, 'example.com', 'mx2.example.com', 300, priority: 20),
    ];

    $response = (new FakeResolver)
        ->stubRecords('example.com', RecordType::MX, $records)
        ->query('example.com', RecordType::MX);

    expect($response->records)->toHaveCount(2)
        ->and($response->records[1]->priority)->toBe(20);
});

it('stubs a failing RCODE', function (): void {
    $response = (new FakeResolver)
        ->stubFailure('example.com', RecordType::A, Rcode::ServFail)
        ->query('example.com', RecordType::A);

    expect($response->isServFail())->toBeTrue()->and($response->succeeded())->toBeFalse();
});

it('throws on an unstubbed query in strict mode', function (): void {
    (new FakeResolver)->strict()->query('unstubbed.example', RecordType::A);
})->throws(ResolutionFailed::class, 'no stub');

it('records queries and asserts they were made', function (): void {
    $fake = new FakeResolver;
    $fake->query('example.com', RecordType::A, '8.8.8.8');

    $fake->assertQueried('example.com', RecordType::A);
    $fake->assertQueried('example.com', RecordType::A, '8.8.8.8');

    expect($fake->queries())->toHaveCount(1)
        ->and($fake->queries()[0])->toBeInstanceOf(QueryRequest::class);
});

it('fails the assertion when no matching query was made', function (): void {
    (new FakeResolver)->assertQueried('example.com', RecordType::A);
})->throws(RuntimeException::class, 'Expected a query');

it('resolves a concurrent batch, preserving order', function (): void {
    $fake = (new FakeResolver)
        ->stub('example.com', RecordType::A, ['1.1.1.1'], nameserver: '8.8.8.8')
        ->stub('example.com', RecordType::A, ['2.2.2.2'], nameserver: '9.9.9.9');

    $responses = $fake->queryConcurrently([
        new QueryRequest('example.com', RecordType::A, '8.8.8.8'),
        new QueryRequest('example.com', RecordType::A, '9.9.9.9'),
    ]);

    expect($responses[0]->values())->toBe(['1.1.1.1'])
        ->and($responses[1]->values())->toBe(['2.2.2.2']);
});
