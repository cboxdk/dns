<?php

declare(strict_types=1);

use Cbox\Dns\Dnssec\DenialOfExistence;
use Cbox\Dns\Dnssec\Exceptions\ExcessiveNsec3Iterations;
use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Tests\Support\DenialFixtures;
use Cbox\Dns\Tests\Support\SignedZones;
use Cbox\Dns\ValueObjects\DnsResponse;

/**
 * RFC 9276: an attacker-chosen NSEC3 iteration count (up to 65535) is a
 * CPU-amplification vector. The validator must refuse a high count BEFORE hashing
 * rather than pay for it, treating the denial as bogus.
 */
it('refuses to compute an NSEC3 hash above the iteration cap (no hashing)', function (): void {
    $denial = new DenialOfExistence;

    expect(fn (): string => $denial->nsec3Hash('example.com', DenialOfExistence::MAX_NSEC3_ITERATIONS + 1, ''))
        ->toThrow(ExcessiveNsec3Iterations::class);

    // At the cap it still computes (no false-reject of legitimate low counts).
    expect(strlen($denial->nsec3Hash('example.com', DenialOfExistence::MAX_NSEC3_ITERATIONS, '')))->toBe(20);
});

it('is BOGUS for a NODATA denial that relies on a high-iteration NSEC3', function (): void {
    [$validator, $resolver, $signers] = SignedZones::hierarchy(['example.com']);

    $salt = '';
    $iterations = 5000; // far above the cap — a DoS-shaped denial
    $ownerHash = SignedZones::nsec3HashRaw('nodata.example.com', $iterations, $salt);

    // A NODATA NSEC3 that would match nodata.example.com if we agreed to hash it.
    $nsec3 = DenialFixtures::nsec3($ownerHash, str_repeat("\xff", 20), $iterations, $salt, [RecordType::A], 'example.com');
    $rrsig = $signers['example.com']->signRrset(RecordType::NSEC3, [$nsec3]);

    $resolver->stubResponse('nodata.example.com', RecordType::TXT, new DnsResponse(
        RecordType::TXT,
        'nodata.example.com',
        [],
        null,
        true,
        false,
        [],
        [$nsec3, $rrsig],
    ));

    expect($validator->validateRecords('nodata.example.com', RecordType::TXT)->isBogus())->toBeTrue();
});
