<?php

declare(strict_types=1);

use Cbox\Dns\Dnssec\DsVerifier;
use Cbox\Dns\Dnssec\Enums\Algorithm;
use Cbox\Dns\Dnssec\Records\Ds;
use Cbox\Dns\Tests\Support\ZoneSigner;

it('matches a synthetic SHA-384 (digest type 4) DS', function (): void {
    $signer = new ZoneSigner(Algorithm::ECDSAP256SHA256, 'example.com');
    $ds = $signer->ds(digestType: 4);

    expect((new DsVerifier)->matches($ds, $signer->dnskey(), 'example.com'))->toBeTrue();
});

it('matches a synthetic SHA-256 (digest type 2) DS', function (): void {
    $signer = new ZoneSigner(Algorithm::RSASHA256, 'example.com');
    $ds = $signer->ds(digestType: 2);

    expect((new DsVerifier)->matches($ds, $signer->dnskey(), 'example.com'))->toBeTrue();
});

it('rejects an unsupported digest type (SHA-1, type 1)', function (): void {
    $signer = new ZoneSigner(Algorithm::ECDSAP256SHA256, 'example.com');
    $key = $signer->dnskey();

    // Hand-build a DS with digest type 1 whose SHA-1 digest is otherwise correct.
    $digest = hash('sha1', "\x07example\x03com\x00".$key->rdata, true);
    $ds = Ds::fromParts($key->keyTag(), $key->algorithm, 1, $digest);

    expect((new DsVerifier)->matches($ds, $key, 'example.com'))->toBeFalse();
});

it('rejects a DS whose key tag or algorithm does not match', function (): void {
    $signer = new ZoneSigner(Algorithm::ECDSAP256SHA256, 'example.com');
    $key = $signer->dnskey();
    $verifier = new DsVerifier;

    $wrongTag = Ds::fromParts($key->keyTag() ^ 0x01, $key->algorithm, 2, $signer->ds()->digest);
    $wrongAlg = Ds::fromParts($key->keyTag(), 8, 2, $signer->ds()->digest);

    expect($verifier->matches($wrongTag, $key, 'example.com'))->toBeFalse()
        ->and($verifier->matches($wrongAlg, $key, 'example.com'))->toBeFalse();
});

it('rejects a DS whose digest does not match the key', function (): void {
    $signer = new ZoneSigner(Algorithm::ECDSAP256SHA256, 'example.com');
    $other = new ZoneSigner(Algorithm::ECDSAP256SHA256, 'example.com');

    // The DS commits to a different key's digest under a matching tag/algorithm.
    $key = $signer->dnskey();
    $ds = Ds::fromParts($key->keyTag(), $key->algorithm, 2, $other->ds()->digest);

    expect((new DsVerifier)->matches($ds, $key, 'example.com'))->toBeFalse();
});
