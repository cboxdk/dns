<?php

declare(strict_types=1);

use Cbox\Dns\Dnssec\DsVerifier;
use Cbox\Dns\Dnssec\Records\Dnskey;
use Cbox\Dns\Dnssec\Records\Rrsig;
use Cbox\Dns\Dnssec\SignatureVerifier;
use Cbox\Dns\Dnssec\Testing\FrozenClock;
use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Tests\Support\Vectors;
use Cbox\Dns\ValueObjects\DnsRecord;

// The load-bearing tests: genuine captured cloudflare.com wire bytes prove the
// ECDSA P-256/SHA-256 signature path and the SHA-256 DS digest path end to end.

it('verifies the real RRSIG(DNSKEY) with the matching KSK (positive)', function (): void {
    $response = Vectors::dnskeyResponse();
    $verifier = new SignatureVerifier(new FrozenClock(Vectors::WITHIN_VALIDITY));

    $verified = $verifier->verify(
        Vectors::dnskeyRrsig(),
        RecordType::DNSKEY,
        $response->records,
        Vectors::ksk(),
        'cloudflare.com',
    );

    expect($verified)->toBeTrue();
});

it('rejects the real RRSIG(DNSKEY) when one signature byte is flipped (negative)', function (): void {
    $response = Vectors::dnskeyResponse();
    $rrsigRecord = $response->answerOfType(RecordType::RRSIG)[0];
    $raw = (string) $rrsigRecord->raw;

    // Flip the final octet of the signature.
    $raw[strlen($raw) - 1] = $raw[strlen($raw) - 1] ^ "\xFF";

    $verifier = new SignatureVerifier(new FrozenClock(Vectors::WITHIN_VALIDITY));

    $verified = $verifier->verify(
        Rrsig::fromRdata($raw),
        RecordType::DNSKEY,
        $response->records,
        Vectors::ksk(),
        'cloudflare.com',
    );

    expect($verified)->toBeFalse();
});

it('rejects the real RRSIG(DNSKEY) when the signed RRset is tampered (negative)', function (): void {
    $response = Vectors::dnskeyResponse();

    // Corrupt one DNSKEY record's RDATA so the reconstructed signed data differs.
    $records = $response->records;
    $first = $records[0];
    $mutatedRaw = (string) $first->raw;
    $mutatedRaw[strlen($mutatedRaw) - 1] = $mutatedRaw[strlen($mutatedRaw) - 1] ^ "\x01";
    $records[0] = new DnsRecord(
        $first->type,
        $first->name,
        $first->value,
        $first->ttl,
        $first->priority,
        $mutatedRaw,
    );

    $verifier = new SignatureVerifier(new FrozenClock(Vectors::WITHIN_VALIDITY));

    expect($verifier->verify(Vectors::dnskeyRrsig(), RecordType::DNSKEY, $records, Vectors::ksk(), 'cloudflare.com'))
        ->toBeFalse();
});

it('verifies the real .com DS against the cloudflare KSK (positive)', function (): void {
    $matched = (new DsVerifier)->matches(Vectors::ds(), Vectors::ksk(), 'cloudflare.com');

    expect($matched)->toBeTrue()
        ->and(Vectors::ds()->keyTag)->toBe(2371)
        ->and(Vectors::ds()->digestType)->toBe(2);
});

it('rejects the real DS against the wrong (ZSK) key and wrong owner (negative)', function (): void {
    $verifier = new DsVerifier;

    expect($verifier->matches(Vectors::ds(), Vectors::zsk(), 'cloudflare.com'))->toBeFalse()
        ->and($verifier->matches(Vectors::ds(), Vectors::ksk(), 'example.com'))->toBeFalse();
});

it('computes the RFC 4034 App. B key tags of the real DNSKEYs', function (): void {
    $tags = array_map(
        static fn ($r): int => Dnskey::fromRdata((string) $r->raw)->keyTag(),
        Vectors::dnskeyResponse()->records,
    );

    expect($tags)->toContain(2371)->toContain(34505);
});
