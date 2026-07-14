<?php

declare(strict_types=1);

use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Tests\Support\DenialFixtures;
use Cbox\Dns\Tests\Support\SignedZones;
use Cbox\Dns\Tests\Support\ZoneSigner;
use Cbox\Dns\ValueObjects\DnsRecord;
use Cbox\Dns\ValueObjects\DnsResponse;

/**
 * RFC 4035 §5.3.4: an answer synthesised from a wildcard (RRSIG label count below
 * the query owner's) is only trustworthy with an accompanying authenticated
 * NSEC/NSEC3 proving the QNAME has no closer match. Without it a MITM can present
 * the wildcard RR under a name that ought to have its own explicit answer.
 */

/**
 * A wildcard-synthesised A response: the A RR is owned by `$owner` but the RRSIG
 * carries `labels: 2` (example.com), i.e. it was produced by `*.example.com`.
 */
function wildcardAnswer(ZoneSigner $signer, string $owner, array $authority = []): DnsResponse
{
    $a = new DnsRecord(RecordType::A, $owner, '192.0.2.99', 300, null, inet_pton('192.0.2.99'));
    $rrsig = $signer->signRrset(RecordType::A, [$a], labels: 2);

    return new DnsResponse(
        RecordType::A,
        $owner,
        [$a],
        null,
        true,
        false,
        [$a, $rrsig],
        $authority,
    );
}

it('is BOGUS for a wildcard answer served without a no-closer-match proof', function (): void {
    [$validator, $resolver, $signers] = SignedZones::hierarchy(['example.com']);

    // The wildcard *.example.com signature is genuine, but `secure.example.com`
    // ought to have its own explicit record — with no NSEC proof we cannot tell,
    // so the answer must be refused.
    $resolver->stubResponse('secure.example.com', RecordType::A, wildcardAnswer(
        $signers['example.com'],
        'secure.example.com',
    ));

    expect($validator->validateRecords('secure.example.com', RecordType::A)->isBogus())->toBeTrue();
});

it('validates a genuine wildcard hit WITH a no-closer-match NSEC as SECURE', function (): void {
    [$validator, $resolver, $signers] = SignedZones::hierarchy(['example.com']);

    // An NSEC spanning the apex up to zzz.example.com covers absent.example.com,
    // proving it has no explicit match — the wildcard expansion is legitimate.
    $nsec = DenialFixtures::nsec('example.com', 'zzz.example.com', [
        RecordType::A, RecordType::SOA, RecordType::NS, RecordType::NSEC, RecordType::RRSIG,
    ]);
    $nsecRrsig = $signers['example.com']->signRrset(RecordType::NSEC, [$nsec]);

    $resolver->stubResponse('absent.example.com', RecordType::A, wildcardAnswer(
        $signers['example.com'],
        'absent.example.com',
        [$nsec, $nsecRrsig],
    ));

    expect($validator->validateRecords('absent.example.com', RecordType::A)->isSecure())->toBeTrue();
});
