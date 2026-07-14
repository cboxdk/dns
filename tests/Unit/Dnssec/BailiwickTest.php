<?php

declare(strict_types=1);

use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Tests\Support\DenialFixtures;
use Cbox\Dns\Tests\Support\SignedZones;
use Cbox\Dns\ValueObjects\DnsResponse;

/**
 * RFC 4035 §5.3.1 requires the RRSIG signer name to be the zone that CONTAINS the
 * RRset. Without that binding, any zone whose own chain validates (an attacker who
 * legitimately holds evil.com's ZSK) can sign another zone's records and have the
 * validator return `secure`. These tests build a real, DS-anchored `evil.com`
 * zone and assert its cross-zone forgeries are `bogus`, while the honest same-zone
 * answers still validate `secure` (no false-reject).
 */

// --- CRITICAL: cross-zone A-record forgery ---------------------------------

it('is BOGUS when a foreign zone (evil.com) signs a victim.com A RRset', function (): void {
    [$validator, $resolver, $signers] = SignedZones::hierarchy(['victim.com', 'evil.com']);

    // evil.com holds its own valid chain and signs a victim.com A RRset. The
    // answer owner is victim.com; only the RRSIG signer betrays the forgery.
    $resolver->stubResponse('victim.com', RecordType::A, SignedZones::signedA(
        $signers['evil.com'],
        'victim.com',
        '192.0.2.66',
    ));

    expect($validator->validateRecords('victim.com', RecordType::A)->isBogus())->toBeTrue();
});

it('validates the honest same-zone A RRset as SECURE (no false-reject)', function (): void {
    [$validator, $resolver, $signers] = SignedZones::hierarchy(['victim.com']);

    $resolver->stubResponse('www.victim.com', RecordType::A, SignedZones::signedA(
        $signers['victim.com'],
        'www.victim.com',
        '192.0.2.7',
    ));

    expect($validator->validateRecords('www.victim.com', RecordType::A)->isSecure())->toBeTrue();
});

it('is BOGUS when an answer record is not owned by the queried name', function (): void {
    [$validator, $resolver, $signers] = SignedZones::hierarchy(['victim.com']);

    // Legitimately signed by victim.com, but for a DIFFERENT owner name than the
    // one that was queried — a spliced RRset.
    $resolver->stubResponse('www.victim.com', RecordType::A, SignedZones::signedA(
        $signers['victim.com'],
        'other.victim.com',
        '192.0.2.7',
    ));

    expect($validator->validateRecords('www.victim.com', RecordType::A)->isBogus())->toBeTrue();
});

// --- CRITICAL: cross-zone NSEC denial --------------------------------------

it('is BOGUS when evil.com signs an NSEC denial for victim.com', function (): void {
    [$validator, $resolver, $signers] = SignedZones::hierarchy(['victim.com', 'evil.com']);

    // A well-formed NODATA NSEC at victim.com (no TXT), but signed by evil.com.
    $nsec = DenialFixtures::nsec('victim.com', 'zzz.victim.com', [RecordType::A, RecordType::NSEC, RecordType::RRSIG]);
    $rrsig = $signers['evil.com']->signRrset(RecordType::NSEC, [$nsec]);

    $resolver->stubResponse('victim.com', RecordType::TXT, new DnsResponse(
        RecordType::TXT,
        'victim.com',
        [],
        null,
        true,
        false,
        [],
        [$nsec, $rrsig],
    ));

    expect($validator->validateRecords('victim.com', RecordType::TXT)->isBogus())->toBeTrue();
});

it('validates the honest same-zone NSEC denial as SECURE (no false-reject)', function (): void {
    [$validator, $resolver, $signers] = SignedZones::hierarchy(['victim.com']);

    $nsec = DenialFixtures::nsec('victim.com', 'zzz.victim.com', [RecordType::A, RecordType::NSEC, RecordType::RRSIG]);
    $rrsig = $signers['victim.com']->signRrset(RecordType::NSEC, [$nsec]);

    $resolver->stubResponse('victim.com', RecordType::TXT, new DnsResponse(
        RecordType::TXT,
        'victim.com',
        [],
        null,
        true,
        false,
        [],
        [$nsec, $rrsig],
    ));

    expect($validator->validateRecords('victim.com', RecordType::TXT)->isSecure())->toBeTrue();
});

// --- CRITICAL: cross-zone NSEC3 denial -------------------------------------

it('is BOGUS when evil.com signs an NSEC3 denial for victim.com', function (): void {
    [$validator, $resolver, $signers] = SignedZones::hierarchy(['victim.com', 'evil.com']);

    $salt = '';
    $iterations = 0;
    $ownerHash = SignedZones::nsec3HashRaw('victim.com', $iterations, $salt);

    // NODATA NSEC3 matching victim.com (no TXT), but the RRSIG signer is evil.com.
    $nsec3 = DenialFixtures::nsec3($ownerHash, str_repeat("\xff", 20), $iterations, $salt, [RecordType::A], 'victim.com');
    $rrsig = $signers['evil.com']->signRrset(RecordType::NSEC3, [$nsec3]);

    $resolver->stubResponse('victim.com', RecordType::TXT, new DnsResponse(
        RecordType::TXT,
        'victim.com',
        [],
        null,
        true,
        false,
        [],
        [$nsec3, $rrsig],
    ));

    expect($validator->validateRecords('victim.com', RecordType::TXT)->isBogus())->toBeTrue();
});
