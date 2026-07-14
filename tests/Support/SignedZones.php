<?php

declare(strict_types=1);

namespace Cbox\Dns\Tests\Support;

use Cbox\Dns\Dnssec\DnssecValidator;
use Cbox\Dns\Dnssec\Enums\Algorithm;
use Cbox\Dns\Dnssec\SignatureVerifier;
use Cbox\Dns\Dnssec\Support\WireName;
use Cbox\Dns\Dnssec\Testing\FrozenClock;
use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Testing\FakeResolver;
use Cbox\Dns\ValueObjects\DnsRecord;
use Cbox\Dns\ValueObjects\DnsResponse;

/**
 * Offline signed-zone scaffolding for the DNSSEC security regression tests. Each
 * zone gets a real runtime keypair via {@see ZoneSigner}; DNSKEY RRsets are
 * self-signed and DS records are signed by the parent, so the chain walker sees
 * a genuine root -> TLD -> zone hierarchy driven entirely through a
 * {@see FakeResolver} — no network.
 */
final class SignedZones
{
    /**
     * Build a resolver seeded with a signed root -> `com` -> each named child
     * hierarchy, plus a validator anchored on the generated root DS.
     *
     * @param  list<string>  $children  zones under `com` to anchor (e.g. victim.com)
     * @return array{0: DnssecValidator, 1: FakeResolver, 2: array<string, ZoneSigner>}
     */
    public static function hierarchy(array $children, int $now = 2_000_000_000): array
    {
        $resolver = new FakeResolver;

        $root = new ZoneSigner(Algorithm::ECDSAP256SHA256, '');
        $com = new ZoneSigner(Algorithm::ECDSAP256SHA256, 'com');

        self::stubDnskey($resolver, $root);
        self::stubDnskey($resolver, $com);
        self::stubDs($resolver, $com, $root);

        $signers = ['root' => $root, 'com' => $com];

        foreach ($children as $child) {
            $signer = new ZoneSigner(Algorithm::ECDSAP256SHA256, $child);
            self::stubDnskey($resolver, $signer);
            self::stubDs($resolver, $signer, $com);
            $signers[$child] = $signer;
        }

        $validator = new DnssecValidator(
            $resolver,
            new SignatureVerifier(new FrozenClock($now)),
            trustAnchors: [$root->ds()],
        );

        return [$validator, $resolver, $signers];
    }

    public static function stubDnskey(FakeResolver $resolver, ZoneSigner $signer): void
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

    public static function stubDs(FakeResolver $resolver, ZoneSigner $child, ZoneSigner $parent): void
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

    /**
     * The raw iterated-SHA1 NSEC3 hash (RFC 5155 §5) computed WITHOUT the
     * production cap — used only to construct high-iteration attack fixtures the
     * validator must refuse.
     */
    public static function nsec3HashRaw(string $name, int $iterations, string $salt): string
    {
        $hash = hash('sha1', WireName::canonical($name).$salt, binary: true);

        for ($i = 0; $i < $iterations; $i++) {
            $hash = hash('sha1', $hash.$salt, binary: true);
        }

        return $hash;
    }

    /**
     * Build a signed A-record answer response owned by `$owner`, signed by
     * `$signer` (whose zone drives the RRSIG signer name).
     */
    public static function signedA(ZoneSigner $signer, string $owner, string $ip, ?int $labels = null): DnsResponse
    {
        $a = new DnsRecord(RecordType::A, $owner, $ip, 300, null, inet_pton($ip));
        $rrsig = $signer->signRrset(RecordType::A, [$a], labels: $labels);

        return new DnsResponse(
            RecordType::A,
            $owner,
            [$a],
            null,
            true,
            false,
            [$a, $rrsig],
        );
    }
}
