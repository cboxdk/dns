<?php

declare(strict_types=1);

use Cbox\Dns\Dnssec\Enums\Algorithm;
use Cbox\Dns\Dnssec\Records\Dnskey;
use Cbox\Dns\Dnssec\Records\Rrsig;
use Cbox\Dns\Dnssec\SignatureVerifier;
use Cbox\Dns\Dnssec\Testing\FrozenClock;
use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Tests\Support\ZoneSigner;
use Cbox\Dns\ValueObjects\DnsRecord;

// Synthetic-but-real crypto: keypairs generated at runtime via OpenSSL/libsodium,
// signing real canonical data. Covers the algorithms with no captured fixture
// (RSA-SHA256, ECDSA P-384, Ed25519) plus every deny-by-default rejection path.

function txtRrset(string $owner = 'example.com'): array
{
    $one = "\x03abc";
    $two = "\x03xyz";

    return [
        new DnsRecord(RecordType::TXT, $owner, 'abc', 3600, null, $one),
        new DnsRecord(RecordType::TXT, $owner, 'xyz', 3600, null, $two),
    ];
}

it('verifies a synthetic RSA-SHA256 signature (real OpenSSL round-trip)', function (): void {
    $signer = new ZoneSigner(Algorithm::RSASHA256, 'example.com');
    $rrset = txtRrset();
    $rrsig = Rrsig::fromRdata((string) $signer->signRrset(RecordType::TXT, $rrset)->raw);

    $ok = (new SignatureVerifier(new FrozenClock(2_000_000_000)))
        ->verify($rrsig, RecordType::TXT, $rrset, $signer->dnskey(), 'example.com');

    expect($ok)->toBeTrue();
});

it('verifies a synthetic ECDSA P-384/SHA-384 signature', function (): void {
    $signer = new ZoneSigner(Algorithm::ECDSAP384SHA384, 'example.com');
    $rrset = txtRrset();
    $rrsig = Rrsig::fromRdata((string) $signer->signRrset(RecordType::TXT, $rrset)->raw);

    $ok = (new SignatureVerifier(new FrozenClock(2_000_000_000)))
        ->verify($rrsig, RecordType::TXT, $rrset, $signer->dnskey(), 'example.com');

    expect($ok)->toBeTrue();
});

it('verifies a synthetic Ed25519 signature (libsodium round-trip)', function (): void {
    $signer = new ZoneSigner(Algorithm::ED25519, 'example.com');
    $rrset = txtRrset();
    $rrsig = Rrsig::fromRdata((string) $signer->signRrset(RecordType::TXT, $rrset)->raw);

    $ok = (new SignatureVerifier(new FrozenClock(2_000_000_000)))
        ->verify($rrsig, RecordType::TXT, $rrset, $signer->dnskey(), 'example.com');

    expect($ok)->toBeTrue();
});

it('rejects an RRSIG outside its validity window (expired and not-yet-valid)', function (): void {
    $signer = new ZoneSigner(Algorithm::ECDSAP256SHA256, 'example.com');
    $rrset = txtRrset();
    $rrsig = Rrsig::fromRdata((string) $signer->signRrset(
        RecordType::TXT,
        $rrset,
        inception: 1_700_000_000,
        expiration: 1_800_000_000,
    )->raw);

    $expired = (new SignatureVerifier(new FrozenClock(1_900_000_000)))
        ->verify($rrsig, RecordType::TXT, $rrset, $signer->dnskey(), 'example.com');

    $notYet = (new SignatureVerifier(new FrozenClock(1_600_000_000)))
        ->verify($rrsig, RecordType::TXT, $rrset, $signer->dnskey(), 'example.com');

    $inWindow = (new SignatureVerifier(new FrozenClock(1_750_000_000)))
        ->verify($rrsig, RecordType::TXT, $rrset, $signer->dnskey(), 'example.com');

    expect($expired)->toBeFalse()
        ->and($notYet)->toBeFalse()
        ->and($inWindow)->toBeTrue();
});

it('rejects an unknown signing algorithm (deny-by-default)', function (): void {
    // Craft an RRSIG with algorithm 99 (unassigned) and a matching key so only
    // the unknown-algorithm rule can be the reason for rejection.
    $signerName = "\x07example\x03com\x00";
    $prefix = pack('n', RecordType::TXT->code())
        .chr(99)                 // unknown algorithm
        .chr(2)                  // labels
        .pack('N', 3600)
        .pack('N', 4_000_000_000)
        .pack('N', 1_700_000_000)
        .pack('n', 12345)
        .$signerName;
    $rrsig = Rrsig::fromRdata($prefix.str_repeat("\x00", 64));

    $bogusKeyRdata = pack('n', 257).chr(3).chr(99).str_repeat("\x00", 32);
    $bogusKey = Dnskey::fromRdata($bogusKeyRdata);

    $ok = (new SignatureVerifier(new FrozenClock(2_000_000_000)))
        ->verify($rrsig, RecordType::TXT, txtRrset(), $bogusKey, 'example.com');

    expect($ok)->toBeFalse();
});

it('rejects a key-tag mismatch, an algorithm mismatch, and a signer mismatch', function (): void {
    $signer = new ZoneSigner(Algorithm::ECDSAP256SHA256, 'example.com');
    $rrset = txtRrset();
    $rrsig = Rrsig::fromRdata((string) $signer->signRrset(RecordType::TXT, $rrset)->raw);
    $verifier = new SignatureVerifier(new FrozenClock(2_000_000_000));

    // A different key (different tag) must not verify.
    $otherKey = (new ZoneSigner(Algorithm::ECDSAP256SHA256, 'example.com'))->dnskey();

    expect($verifier->verify($rrsig, RecordType::TXT, $rrset, $otherKey, 'example.com'))->toBeFalse()
        // Correct key but wrong expected signer zone.
        ->and($verifier->verify($rrsig, RecordType::TXT, $rrset, $signer->dnskey(), 'evil.com'))->toBeFalse()
        // Correct key but wrong covered type.
        ->and($verifier->verify($rrsig, RecordType::A, $rrset, $signer->dnskey(), 'example.com'))->toBeFalse();
});

it('rejects a signature made with a non-zone key', function (): void {
    // flags 0 → Zone Key bit clear; such a key must never validate zone data.
    $signer = new ZoneSigner(Algorithm::ECDSAP256SHA256, 'example.com', flags: 0);
    $rrset = txtRrset();
    $rrsig = Rrsig::fromRdata((string) $signer->signRrset(RecordType::TXT, $rrset)->raw);

    $ok = (new SignatureVerifier(new FrozenClock(2_000_000_000)))
        ->verify($rrsig, RecordType::TXT, $rrset, $signer->dnskey(), 'example.com');

    expect($ok)->toBeFalse();
});
