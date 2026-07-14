<?php

declare(strict_types=1);

use Cbox\Dns\Dnssec\DenialOfExistence;
use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Tests\Support\DenialFixtures;

// NSEC ----------------------------------------------------------------------

it('proves NODATA with a matching NSEC that lacks the queried type', function (): void {
    $nsec = DenialFixtures::nsec('a.example.com', 'c.example.com', [RecordType::A, RecordType::AAAA]);
    $denial = new DenialOfExistence;

    expect($denial->nsecProvesNoData('a.example.com', RecordType::TXT, [$nsec]))->toBeTrue()
        // The type IS present → not a NODATA proof.
        ->and($denial->nsecProvesNoData('a.example.com', RecordType::A, [$nsec]))->toBeFalse();
});

it('proves NXDOMAIN with an NSEC covering the name and the wildcard', function (): void {
    $coversName = DenialFixtures::nsec('a.example.com', 'c.example.com', [RecordType::A]);
    $coversWildcard = DenialFixtures::nsec('example.com', 'a.example.com', [RecordType::SOA, RecordType::NS]);
    $denial = new DenialOfExistence;

    expect($denial->nsecProvesNxDomain('b.example.com', [$coversName, $coversWildcard]))->toBeTrue();
});

it('does NOT prove NXDOMAIN when no NSEC covers the name', function (): void {
    $nsec = DenialFixtures::nsec('x.example.com', 'z.example.com', [RecordType::A]);

    expect((new DenialOfExistence)->nsecProvesNxDomain('b.example.com', [$nsec]))->toBeFalse();
});

it('proves an insecure delegation via an NSEC without the DS bit', function (): void {
    // Delegation NSEC: NS present, DS and SOA absent.
    $nsec = DenialFixtures::nsec('sub.example.com', 'zzz.example.com', [RecordType::NS]);
    $denial = new DenialOfExistence;

    expect($denial->provesNoDs('sub.example.com', [$nsec], []))->toBeTrue()
        // A signed (DS present) delegation is NOT an insecure one.
        ->and($denial->provesNoDs('sub.example.com', [
            DenialFixtures::nsec('sub.example.com', 'zzz.example.com', [RecordType::NS, RecordType::DS]),
        ], []))->toBeFalse();
});

// NSEC3 ---------------------------------------------------------------------

it('proves NODATA with a matching NSEC3 that lacks the queried type', function (): void {
    $denial = new DenialOfExistence;
    $salt = "\xaa\xbb";
    $hash = $denial->nsec3Hash('a.example.com', 3, $salt);

    $nsec3 = DenialFixtures::nsec3($hash, str_repeat("\xff", 20), 3, $salt, [RecordType::A], 'example.com');

    expect($denial->nsec3ProvesNoData('a.example.com', RecordType::TXT, [$nsec3]))->toBeTrue()
        ->and($denial->nsec3ProvesNoData('a.example.com', RecordType::A, [$nsec3]))->toBeFalse();
});

it('proves NXDOMAIN with the NSEC3 closest-encloser proof', function (): void {
    $denial = new DenialOfExistence;
    $salt = '';
    $iterations = 0;
    $qname = 'x.example.com';

    $hCe = $denial->nsec3Hash('example.com', $iterations, $salt);

    // Matching NSEC3 for the closest encloser (example.com).
    $matchCe = DenialFixtures::nsec3($hCe, str_repeat("\xff", 20), $iterations, $salt, [RecordType::SOA, RecordType::NS], 'example.com');

    // A wide covering NSEC3 (owner 0x00.., next 0xff..) covers both the
    // next-closer name and the wildcard.
    $wideCover = DenialFixtures::nsec3(str_repeat("\x00", 20), str_repeat("\xff", 20), $iterations, $salt, [], 'example.com');

    expect($denial->nsec3ProvesNxDomain($qname, [$matchCe, $wideCover]))->toBeTrue();
});

it('proves an insecure delegation via an Opt-Out NSEC3 that covers the name', function (): void {
    $denial = new DenialOfExistence;
    $salt = "\x01\x02";
    $iterations = 5;

    // Opt-out NSEC3 spanning the (unsigned) child's hash.
    $optOut = DenialFixtures::nsec3(
        str_repeat("\x00", 20),
        str_repeat("\xff", 20),
        $iterations,
        $salt,
        [RecordType::NS],
        'example.com',
        optOut: true,
    );

    expect($denial->provesNoDs('unsigned.example.com', [], [$optOut]))->toBeTrue();
});

it('recomputes NSEC3 hashes deterministically for a known name', function (): void {
    $denial = new DenialOfExistence;

    // Iterating changes the digest; salt changes the digest; determinism holds.
    expect($denial->nsec3Hash('example.com', 0, ''))
        ->toBe($denial->nsec3Hash('example.com', 0, ''))
        ->and($denial->nsec3Hash('example.com', 1, ''))
        ->not->toBe($denial->nsec3Hash('example.com', 0, ''))
        ->and(strlen($denial->nsec3Hash('example.com', 10, "\xaa")))->toBe(20);
});
