<?php

declare(strict_types=1);

use Cbox\Dns\Contracts\Resolver;
use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Exceptions\ResolutionFailed;
use Cbox\Dns\Resolvers\AuthoritativeResolver;
use Cbox\Dns\Testing\FakeResolver;
use Cbox\Dns\ValueObjects\DnsResponse;

it('discovers authoritative nameserver IPs from NS then A/AAAA records', function (): void {
    $fake = (new FakeResolver)
        ->stub('example.com', RecordType::NS, ['ns1.example.com', 'ns2.example.com'])
        ->stub('ns1.example.com', RecordType::A, ['192.0.2.1'])
        ->stub('ns2.example.com', RecordType::A, ['192.0.2.2'])
        ->stub('ns2.example.com', RecordType::AAAA, ['2001:db8::2']);

    $ips = (new AuthoritativeResolver($fake))->authoritativeFor('example.com');

    expect($ips)->toBe(['192.0.2.1', '192.0.2.2', '2001:db8::2']);
});

it('queries the target record directly against an authoritative NS with recursion off', function (): void {
    $fake = (new FakeResolver)
        ->stub('example.com', RecordType::NS, ['ns1.example.com'])
        ->stub('ns1.example.com', RecordType::A, ['192.0.2.1'])
        // Stubbed per-nameserver-IP: this is the authoritative view.
        ->stub('www.example.com', RecordType::A, ['93.184.216.34'], nameserver: '192.0.2.1');

    $response = (new AuthoritativeResolver($fake))->query('www.example.com', RecordType::A, 'example.com');

    expect($response->values())->toBe(['93.184.216.34'])
        ->and($response->nameserver)->toBe('192.0.2.1');
});

it('falls through to the next NS IP when the first fails, surfacing the answer', function (): void {
    $delegate = (new FakeResolver)
        ->stub('example.com', RecordType::NS, ['ns1.example.com', 'ns2.example.com'])
        ->stub('ns1.example.com', RecordType::A, ['192.0.2.1'])
        ->stub('ns2.example.com', RecordType::A, ['192.0.2.2'])
        ->stub('www.example.com', RecordType::A, ['93.184.216.34'], nameserver: '192.0.2.2');

    // The first authoritative IP is unreachable; the second answers.
    $flaky = new class($delegate) implements Resolver
    {
        public function __construct(private readonly FakeResolver $delegate) {}

        public function query(string $host, RecordType $type, ?string $nameserver = null, bool $recursion = true): DnsResponse
        {
            if ($nameserver === '192.0.2.1' && $host === 'www.example.com') {
                throw ResolutionFailed::make($nameserver, 'timed out');
            }

            return $this->delegate->query($host, $type, $nameserver, $recursion);
        }
    };

    $response = (new AuthoritativeResolver($flaky))->query('www.example.com', RecordType::A, 'example.com');

    expect($response->values())->toBe(['93.184.216.34'])
        ->and($response->nameserver)->toBe('192.0.2.2');
});

it('throws ResolutionFailed when the zone exposes no nameservers', function (): void {
    (new AuthoritativeResolver(new FakeResolver))->query('www.example.com', RecordType::A, 'example.com');
})->throws(ResolutionFailed::class);
