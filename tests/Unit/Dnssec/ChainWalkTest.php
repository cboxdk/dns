<?php

declare(strict_types=1);

use Cbox\Dns\Dnssec\DnssecValidator;
use Cbox\Dns\Dnssec\Enums\Algorithm;
use Cbox\Dns\Dnssec\SignatureVerifier;
use Cbox\Dns\Dnssec\Testing\FrozenClock;
use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Testing\FakeResolver;
use Cbox\Dns\Tests\Support\DenialFixtures;
use Cbox\Dns\Tests\Support\ZoneSigner;
use Cbox\Dns\ValueObjects\DnsRecord;
use Cbox\Dns\ValueObjects\DnsResponse;

/**
 * Assemble a full offline signed hierarchy: root -> com -> example.com, each a
 * single CSK generated at runtime. Returns [validator, resolver, signers].
 *
 * @return array{0: DnssecValidator, 1: FakeResolver, 2: array<string, ZoneSigner>}
 */
function signedHierarchy(int $now = 2_000_000_000): array
{
    $root = new ZoneSigner(Algorithm::ECDSAP256SHA256, '');
    $com = new ZoneSigner(Algorithm::ECDSAP256SHA256, 'com');
    $example = new ZoneSigner(Algorithm::ECDSAP256SHA256, 'example.com');

    $resolver = new FakeResolver;

    // DNSKEY at each zone, self-signed.
    stubDnskey($resolver, $root);
    stubDnskey($resolver, $com);
    stubDnskey($resolver, $example);

    // DS for each child, signed by its parent.
    stubDs($resolver, $com, $root);          // com DS, signed by root
    stubDs($resolver, $example, $com);       // example.com DS, signed by com

    $validator = new DnssecValidator(
        $resolver,
        new SignatureVerifier(new FrozenClock($now)),
        trustAnchors: [$root->ds()],
    );

    return [$validator, $resolver, ['root' => $root, 'com' => $com, 'example' => $example]];
}

function stubDnskey(FakeResolver $resolver, ZoneSigner $signer): void
{
    $dnskey = $signer->dnskeyRecord();
    $rrsig = $signer->signRrset(RecordType::DNSKEY, [$dnskey]);

    $resolver->stubResponse($signer->zone, RecordType::DNSKEY, new DnsResponse(
        RecordType::DNSKEY,
        $signer->zone,
        [$dnskey],
        null,
        true,
        false,
        [$dnskey, $rrsig],
    ));
}

function stubDs(FakeResolver $resolver, ZoneSigner $child, ZoneSigner $parent): void
{
    $ds = $child->dsRecord();
    $rrsig = $parent->signRrset(RecordType::DS, [$ds]);

    $resolver->stubResponse($child->zone, RecordType::DS, new DnsResponse(
        RecordType::DS,
        $child->zone,
        [$ds],
        null,
        true,
        false,
        [$ds, $rrsig],
    ));
}

it('validates a complete signed chain as SECURE', function (): void {
    [$validator] = signedHierarchy();

    $result = $validator->validate('example.com');

    expect($result->isSecure())->toBeTrue()
        ->and($result->dnskeys)->not->toBeEmpty();
});

it('validates a signed record set against the walked chain as SECURE', function (): void {
    [$validator, $resolver, $signers] = signedHierarchy();

    $a = new DnsRecord(RecordType::A, 'www.example.com', '192.0.2.7', 300, null, inet_pton('192.0.2.7'));
    $rrsig = $signers['example']->signRrset(RecordType::A, [$a]);

    $resolver->stubResponse('www.example.com', RecordType::A, new DnsResponse(
        RecordType::A,
        'www.example.com',
        [$a],
        null,
        true,
        false,
        [$a, $rrsig],
    ));

    $result = $validator->validateRecords('www.example.com', RecordType::A);

    expect($result->isSecure())->toBeTrue();
});

it('is BOGUS when a record set carries no valid RRSIG', function (): void {
    [$validator, $resolver, $signers] = signedHierarchy();

    $a = new DnsRecord(RecordType::A, 'www.example.com', '192.0.2.7', 300, null, inet_pton('192.0.2.7'));
    // Sign a DIFFERENT record, then serve the mismatched signature.
    $wrong = new DnsRecord(RecordType::A, 'www.example.com', '203.0.113.9', 300, null, inet_pton('203.0.113.9'));
    $rrsig = $signers['example']->signRrset(RecordType::A, [$wrong]);

    $resolver->stubResponse('www.example.com', RecordType::A, new DnsResponse(
        RecordType::A,
        'www.example.com',
        [$a],
        null,
        true,
        false,
        [$a, $rrsig],
    ));

    expect($validator->validateRecords('www.example.com', RecordType::A)->isBogus())->toBeTrue();
});

it('is BOGUS when the DS link to a zone is broken', function (): void {
    [$validator, $resolver, $signers] = signedHierarchy();

    // Replace example.com's DS with one that commits to a different key.
    $impostor = new ZoneSigner(Algorithm::ECDSAP256SHA256, 'example.com');
    $ds = $impostor->dsRecord();
    $rrsig = $signers['com']->signRrset(RecordType::DS, [$ds]);

    $resolver->stubResponse('example.com', RecordType::DS, new DnsResponse(
        RecordType::DS,
        'example.com',
        [$ds],
        null,
        true,
        false,
        [$ds, $rrsig],
    ));

    expect($validator->validate('example.com')->isBogus())->toBeTrue();
});

it('is BOGUS when the root DNSKEY does not match the trust anchor', function (): void {
    [, $resolver, $signers] = signedHierarchy();

    // Anchor on an unrelated DS: the root key can never match it.
    $stranger = new ZoneSigner(Algorithm::ECDSAP256SHA256, '');
    $validator = new DnssecValidator(
        $resolver,
        new SignatureVerifier(new FrozenClock(2_000_000_000)),
        trustAnchors: [$stranger->ds()],
    );

    expect($validator->validate('example.com')->isBogus())->toBeTrue();
});

it('is BOGUS when the zone signature is expired at validation time', function (): void {
    // Sign with a window that has closed by `now`.
    $root = new ZoneSigner(Algorithm::ECDSAP256SHA256, '');
    $resolver = new FakeResolver;

    $dnskey = $root->dnskeyRecord();
    $rrsig = $root->signRrset(RecordType::DNSKEY, [$dnskey], inception: 1_600_000_000, expiration: 1_700_000_000);
    $resolver->stubResponse('', RecordType::DNSKEY, new DnsResponse(
        RecordType::DNSKEY,
        '',
        [$dnskey],
        null,
        true,
        false,
        [$dnskey, $rrsig],
    ));

    $validator = new DnssecValidator(
        $resolver,
        new SignatureVerifier(new FrozenClock(2_000_000_000)), // past expiration
        trustAnchors: [$root->ds()],
    );

    expect($validator->validate('')->isBogus())->toBeTrue();
});

it('validates the root zone alone as SECURE', function (): void {
    [$validator] = signedHierarchy();

    expect($validator->validate('')->isSecure())->toBeTrue();
});

it('reports INSECURE for a delegation proven unsigned via a signed NSEC', function (): void {
    [$validator, $resolver, $signers] = signedHierarchy();

    // com serves NO DS for example.com, but a signed NSEC proving the delegation
    // has NS and no DS — a genuine unsigned (insecure) delegation.
    $nsec = DenialFixtures::nsec(
        'example.com',
        'zzz.com',
        [RecordType::NS, RecordType::RRSIG, RecordType::NSEC],
    );
    $rrsig = $signers['com']->signRrset(RecordType::NSEC, [$nsec]);

    $resolver->stubResponse('example.com', RecordType::DS, new DnsResponse(
        RecordType::DS,
        'example.com',
        [],              // no DS records
        null,
        true,
        false,
        [],              // empty answer
        [$nsec, $rrsig], // authority: the signed NSEC proof
    ));

    $result = $validator->validate('example.com');

    expect($result->isInsecure())->toBeTrue();
});

it('is BOGUS when a missing DS is not backed by any signed proof', function (): void {
    [$validator, $resolver] = signedHierarchy();

    // No DS and no NSEC/NSEC3 proof at all → cannot conclude insecure → bogus.
    $resolver->stubResponse('example.com', RecordType::DS, new DnsResponse(
        RecordType::DS,
        'example.com',
        [],
        null,
        true,
        false,
        [],
        [],
    ));

    expect($validator->validate('example.com')->isBogus())->toBeTrue();
});
