<?php

declare(strict_types=1);

use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Resolvers\AuthoritativeResolver;
use Cbox\Dns\Testing\FakeResolver;
use Cbox\Dns\Verification\DomainVerifier;

const TOKEN = 'cbox-verify=8f14e45fceea167a5a36dedd4bea2543';

/**
 * Stub the NS + NS-host A records a FakeResolver needs so AuthoritativeResolver
 * can find the authoritative IP (192.0.2.1) for example.com.
 */
function withZone(): FakeResolver
{
    return (new FakeResolver)
        ->stub('example.com', RecordType::NS, ['ns1.example.com'])
        ->stub('ns1.example.com', RecordType::A, ['192.0.2.1']);
}

it('builds the challenge host from a normalized domain', function (): void {
    $verifier = new DomainVerifier(new AuthoritativeResolver(new FakeResolver));

    expect($verifier->challengeHost('  Example.COM.  '))->toBe('_cbox-challenge.example.com');
});

it('verifies true when the token is published at the authoritative nameserver', function (): void {
    $fake = withZone()->stub(
        '_cbox-challenge.example.com',
        RecordType::TXT,
        ['some-other-record', TOKEN],
        nameserver: '192.0.2.1',
    );

    $verifier = new DomainVerifier(new AuthoritativeResolver($fake));

    expect($verifier->verify('Example.com', TOKEN))->toBeTrue();
});

it('verifies false when the challenge record is absent', function (): void {
    $verifier = new DomainVerifier(new AuthoritativeResolver(withZone()));

    expect($verifier->verify('example.com', TOKEN))->toBeFalse();
});

it('requires the authoritative path — a recursive-only token does not verify', function (): void {
    // Token is present in the recursive view (nameserver: null) but the
    // authoritative server (192.0.2.1) serves an empty set. Deny-by-default wins.
    $fake = withZone()
        ->stub('_cbox-challenge.example.com', RecordType::TXT, [TOKEN])                    // recursive view
        ->stub('_cbox-challenge.example.com', RecordType::TXT, [], nameserver: '192.0.2.1'); // authoritative view

    $verifier = new DomainVerifier(new AuthoritativeResolver($fake));

    expect($verifier->verify('example.com', TOKEN))->toBeFalse();
});

it('verifies false when the zone has no authoritative nameservers (resolution failure)', function (): void {
    $verifier = new DomainVerifier(new AuthoritativeResolver(new FakeResolver));

    expect($verifier->verify('example.com', TOKEN))->toBeFalse();
});
