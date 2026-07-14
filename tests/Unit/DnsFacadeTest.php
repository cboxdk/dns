<?php

declare(strict_types=1);

use Cbox\Dns\Dns;
use Cbox\Dns\Dnssec\DnssecValidator;
use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Resolvers\AuthoritativeResolver;
use Cbox\Dns\Testing\FakeResolver;

it('looks up records through the injected resolver', function (): void {
    $fake = (new FakeResolver)->stub('example.com', RecordType::A, ['93.184.216.34']);

    expect((new Dns($fake))->lookup('example.com', RecordType::A)->values())->toBe(['93.184.216.34']);
});

it('verifies a domain end-to-end via the authoritative path', function (): void {
    $fake = (new FakeResolver)
        ->stub('example.com', RecordType::NS, ['ns1.example.com'])
        ->stub('ns1.example.com', RecordType::A, ['192.0.2.1'])
        ->stub('_cbox-challenge.example.com', RecordType::TXT, ['tok-123'], nameserver: '192.0.2.1');

    $dns = new Dns($fake);

    expect($dns->challengeHost('example.com'))->toBe('_cbox-challenge.example.com')
        ->and($dns->verifyDomain('example.com', 'tok-123'))->toBeTrue()
        ->and($dns->verifyDomain('example.com', 'wrong'))->toBeFalse();
});

it('checks propagation end-to-end', function (): void {
    $fake = (new FakeResolver)
        ->stub('example.com', RecordType::NS, ['ns1.example.com'])
        ->stub('ns1.example.com', RecordType::A, ['192.0.2.1'])
        ->stub('www.example.com', RecordType::A, ['93.184.216.34'], nameserver: '192.0.2.1')
        ->stub('www.example.com', RecordType::A, ['93.184.216.34']); // recursive panel matches

    $report = (new Dns($fake))->checkPropagation('www.example.com', RecordType::A, 'example.com');

    expect($report->authoritativeValues)->toBe(['93.184.216.34']);
});

it('exposes the resolver and authoritative seams for DNSSEC and other extensions', function (): void {
    $fake = new FakeResolver;
    $dns = new Dns($fake);

    expect($dns->resolver())->toBe($fake)
        ->and($dns->authoritative())->toBeInstanceOf(AuthoritativeResolver::class);
});

it('exposes a DNSSEC validator that fails closed on an unstubbed resolver', function (): void {
    $dns = new Dns(new FakeResolver);

    // The real IANA root anchors cannot be satisfied by an empty fake resolver,
    // so validation is bogus — never silently secure (deny-by-default).
    expect($dns->dnssec())->toBeInstanceOf(DnssecValidator::class)
        ->and($dns->dnssec()->validate('example.com')->isBogus())->toBeTrue();
});
