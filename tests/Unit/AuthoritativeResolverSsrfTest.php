<?php

declare(strict_types=1);

use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Exceptions\ResolutionFailed;
use Cbox\Dns\Resolvers\AuthoritativeResolver;
use Cbox\Dns\Testing\FakeResolver;

it('refuses to query a nameserver that resolves to an internal address', function (): void {
    // An attacker-controlled zone points its NS at a loopback / cloud-metadata host.
    $fake = (new FakeResolver)
        ->stub('evil.example', RecordType::NS, ['ns.evil.example'])
        ->stub('ns.evil.example', RecordType::A, ['127.0.0.1', '169.254.169.254', '10.0.0.5']);

    $resolver = new AuthoritativeResolver($fake);

    expect($resolver->authoritativeFor('evil.example'))->toBe([]);
});

it('still queries public nameserver addresses', function (): void {
    $fake = (new FakeResolver)
        ->stub('example.com', RecordType::NS, ['ns.example.com'])
        ->stub('ns.example.com', RecordType::A, ['93.184.216.34']);

    expect((new AuthoritativeResolver($fake))->authoritativeFor('example.com'))->toBe(['93.184.216.34']);
});

it('allows internal nameservers when explicitly opted in', function (): void {
    $fake = (new FakeResolver)
        ->stub('internal.test', RecordType::NS, ['ns.internal.test'])
        ->stub('ns.internal.test', RecordType::A, ['10.0.0.53']);

    $resolver = new AuthoritativeResolver($fake, allowNonPublicNameservers: true);

    expect($resolver->authoritativeFor('internal.test'))->toBe(['10.0.0.53']);
});

it('caps the nameserver fan-out a malicious zone can trigger', function (): void {
    $names = [];
    $fake = new FakeResolver;

    for ($i = 0; $i < 50; $i++) {
        $names[] = "ns{$i}.example.com";
        $fake->stub("ns{$i}.example.com", RecordType::A, ['93.184.216.'.($i + 1)]);
    }

    $fake->stub('example.com', RecordType::NS, $names);

    expect(count((new AuthoritativeResolver($fake))->authoritativeFor('example.com')))
        ->toBeLessThanOrEqual(AuthoritativeResolver::MAX_NAMESERVERS);
});

it('surfaces a resolution failure when no public nameserver survives filtering', function (): void {
    $fake = (new FakeResolver)
        ->stub('evil.example', RecordType::NS, ['ns.evil.example'])
        ->stub('ns.evil.example', RecordType::A, ['127.0.0.1']);

    (new AuthoritativeResolver($fake))->query('evil.example', RecordType::TXT, 'evil.example');
})->throws(ResolutionFailed::class);

it('unwraps IPv4-mapped IPv6 so a mapped metadata address is still refused', function (): void {
    $fake = (new FakeResolver)
        ->stub('evil.example', RecordType::NS, ['ns.evil.example'])
        ->stub('ns.evil.example', RecordType::AAAA, ['::ffff:169.254.169.254']);

    expect((new AuthoritativeResolver($fake))->authoritativeFor('evil.example'))->toBe([]);
});
