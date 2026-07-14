<?php

declare(strict_types=1);

use Cbox\Dns\Dnssec\DenialOfExistence;
use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Tests\Support\DenialFixtures;

/**
 * RFC 4035 §5.4: a parent-side delegation NSEC (NS present, SOA absent) lives at
 * the zone cut and cannot speak to the delegated child's own RRsets. It must not
 * be accepted as a NODATA proof at the child, or a MITM could manufacture NODATA
 * for a name that actually holds the queried type in the child zone.
 */
it('rejects a parent-side delegation NSEC as a NODATA proof', function (): void {
    // Delegation NSEC at sub.example.com: NS set, SOA absent, no TXT.
    $delegation = DenialFixtures::nsec('sub.example.com', 'zzz.example.com', [RecordType::NS, RecordType::RRSIG, RecordType::NSEC]);

    expect((new DenialOfExistence)->nsecProvesNoData('sub.example.com', RecordType::TXT, [$delegation]))->toBeFalse();
});

it('still accepts an in-zone NSEC (no NS, or apex NS+SOA) as a NODATA proof', function (): void {
    $denial = new DenialOfExistence;

    // Ordinary in-zone name: neither NS nor SOA.
    $inZone = DenialFixtures::nsec('sub.example.com', 'zzz.example.com', [RecordType::A, RecordType::RRSIG, RecordType::NSEC]);

    // Zone apex: NS *and* SOA present — an authoritative NODATA source.
    $apex = DenialFixtures::nsec('example.com', 'a.example.com', [RecordType::NS, RecordType::SOA, RecordType::RRSIG, RecordType::NSEC]);

    expect($denial->nsecProvesNoData('sub.example.com', RecordType::TXT, [$inZone]))->toBeTrue()
        ->and($denial->nsecProvesNoData('example.com', RecordType::TXT, [$apex]))->toBeTrue();
});
