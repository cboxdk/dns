<?php

declare(strict_types=1);

namespace Cbox\Dns\Dnssec;

use Cbox\Dns\Contracts\Resolver;
use Cbox\Dns\Dnssec\Enums\ValidationStatus;
use Cbox\Dns\Dnssec\Records\Dnskey;
use Cbox\Dns\Dnssec\Records\Ds;
use Cbox\Dns\Dnssec\Records\Rrsig;
use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\ValueObjects\DnsRecord;
use Cbox\Dns\ValueObjects\DnsResponse;

/**
 * The DNSSEC chain walker. Anchored on the IANA root trust anchors, it walks
 * root → TLD → zone: at each level it fetches the DNSKEY RRset (DO bit), proves
 * one key against the DS committed by the parent (the root uses the hard-coded
 * anchor), verifies the zone's self-signature with that key, and only then trusts
 * the zone's keys to authenticate the next step down.
 *
 * Deny-by-default is total: a missing key, a failed signature, a broken DS link,
 * an expired RRSIG, or an unknown algorithm all resolve to `bogus` — never a
 * silent `secure`. The only non-secure "success" is `insecure`, and only when an
 * authenticated NSEC/NSEC3 proof shows the delegation is genuinely unsigned.
 *
 * Trust comes from the cryptography, not the transport: because every signature
 * is checked against an anchored key, the fetch may go through any {@see Resolver}
 * (a recursive DO query, a fake) without weakening the result.
 */
final class DnssecValidator
{
    /** @var list<Ds> */
    private array $trustAnchors;

    /**
     * @param  list<Ds>|null  $trustAnchors  overrides the IANA root anchors — used
     *                                       by tests to anchor a self-generated
     *                                       chain; production uses the default
     */
    public function __construct(
        private readonly Resolver $resolver,
        private readonly SignatureVerifier $signatureVerifier = new SignatureVerifier,
        private readonly DsVerifier $dsVerifier = new DsVerifier,
        private readonly DenialOfExistence $denial = new DenialOfExistence,
        ?array $trustAnchors = null,
    ) {
        $this->trustAnchors = $trustAnchors ?? TrustAnchor::iana();
    }

    /**
     * Validate the authentication chain from the root down to `$zone`.
     */
    public function validate(string $zone): ValidationResult
    {
        return $this->walk($this->normalize($zone));
    }

    /**
     * Validate a specific record set: fetch `$host`/`$type` with the DO bit, learn
     * the signing zone from the RRSIG's signer name, validate that zone's chain,
     * and verify the RRset against the zone's keys. An empty answer is validated
     * as an authenticated NODATA/NXDOMAIN via NSEC/NSEC3, or is bogus.
     */
    public function validateRecords(string $host, RecordType $type): ValidationResult
    {
        $host = $this->normalize($host);
        $response = $this->resolver->query($host, $type, null, true, true);

        if ($response->records !== []) {
            return $this->validatePresent($host, $type, $response);
        }

        return $this->validateAbsent($host, $type, $response);
    }

    // --- record validation --------------------------------------------------

    private function validatePresent(string $host, RecordType $type, DnsResponse $response): ValidationResult
    {
        // Every answer record must be owned by the queried name — a MITM cannot
        // splice in an RRset owned by some other name it happens to hold a key for.
        foreach ($response->records as $record) {
            if ($this->normalize($record->name) !== $host) {
                return ValidationResult::bogus($host, 'an answer record is not owned by the queried name');
            }
        }

        $rrsigs = $response->answerOfType(RecordType::RRSIG);
        $zone = $this->signerFor($rrsigs, $type);

        if ($zone === null) {
            return ValidationResult::bogus($host, "no RRSIG covers the {$type->value} RRset");
        }

        // RFC 4035 §5.3.1: the signer zone must contain the RRset, i.e. be an
        // in-bailiwick (label-aligned) ancestor of the queried name. Without this
        // any zone whose own chain validates could forge another zone's records.
        if (! $this->inBailiwick($zone, $host)) {
            return ValidationResult::bogus($host, "RRSIG signer {$this->label($zone)} is not in-bailiwick for {$host}");
        }

        $chain = $this->walk($zone);

        if (! $chain->isSecure()) {
            return new ValidationResult($chain->status, $host, $chain->reason);
        }

        $rrsig = $this->verifyingRrsig($type, $response->records, $rrsigs, $chain->dnskeys, $zone);

        if ($rrsig === null) {
            return ValidationResult::bogus($host, "no valid RRSIG over the {$type->value} RRset");
        }

        // RFC 4035 §5.3.4: a signature whose label count is below the query owner's
        // was produced by a wildcard. The answer is only trustworthy with an
        // authenticated NSEC/NSEC3 proving the QNAME has no closer (explicit) match.
        if ($rrsig->labels < $this->labelCount($host)
            && ! $this->wildcardNoCloserMatch($host, $rrsig->labels, $response, $chain->dnskeys, $zone)) {
            return ValidationResult::bogus($host, 'wildcard answer lacks an authenticated no-closer-match proof');
        }

        return ValidationResult::secure($host, "{$type->value} RRset verified against zone {$zone}");
    }

    private function validateAbsent(string $host, RecordType $type, DnsResponse $response): ValidationResult
    {
        $rrsigs = $response->authorityOfType(RecordType::RRSIG);
        $zone = $this->anySigner($rrsigs);

        if ($zone === null) {
            return ValidationResult::bogus($host, 'empty answer carried no signatures to validate absence');
        }

        // The zone proving the denial must be an ancestor of the queried name; a
        // denial signed by an unrelated zone proves nothing about this name.
        if (! $this->inBailiwick($zone, $host)) {
            return ValidationResult::bogus($host, "denial signer {$this->label($zone)} is not in-bailiwick for {$host}");
        }

        $chain = $this->walk($zone);

        if (! $chain->isSecure()) {
            return new ValidationResult($chain->status, $host, $chain->reason);
        }

        $nsec = $response->authorityOfType(RecordType::NSEC);
        $nsec3 = $response->authorityOfType(RecordType::NSEC3);

        if (! $this->denialAuthoritySigned($nsec, $nsec3, $rrsigs, $chain->dnskeys, $zone)) {
            return ValidationResult::bogus($host, 'NSEC/NSEC3 proof is not validly signed');
        }

        $proven = $this->denial->nsecProvesNoData($host, $type, $nsec)
            || $this->denial->nsec3ProvesNoData($host, $type, $nsec3)
            || $this->denial->nsecProvesNxDomain($host, $nsec)
            || $this->denial->nsec3ProvesNxDomain($host, $nsec3);

        return $proven
            ? ValidationResult::secure($host, "authenticated denial of existence for {$type->value}")
            : ValidationResult::bogus($host, 'authority section does not prove the name/type is absent');
    }

    // --- chain walk ---------------------------------------------------------

    private function walk(string $zone): ValidationResult
    {
        $trusted = $this->establishZoneKeys('', $this->trustAnchors);

        if ($trusted === null) {
            return ValidationResult::bogus($zone, 'root DNSKEY did not validate against the trust anchor');
        }

        $parent = '';

        foreach ($this->descendants($zone) as $child) {
            [$status, $dsSet] = $this->authenticatedDs($child, $parent, $trusted);

            if ($status === ValidationStatus::Insecure) {
                return ValidationResult::insecure($zone, "delegation to {$child} is provably unsigned");
            }

            if ($status === ValidationStatus::Bogus) {
                return ValidationResult::bogus($zone, "DS for {$child} did not validate at {$this->label($parent)}");
            }

            $childKeys = $this->establishZoneKeys($child, $dsSet);

            if ($childKeys === null) {
                return ValidationResult::bogus($zone, "DNSKEY for {$child} did not validate against its DS");
            }

            $trusted = $childKeys;
            $parent = $child;
        }

        return ValidationResult::secure($zone, "authentication chain to {$this->label($zone)} is complete", $trusted);
    }

    /**
     * Fetch the zone's DNSKEY RRset and return the trusted keys, or null on any
     * failure: a key must match a `$dsSet` entry (the anchored KSK) and the
     * DNSKEY RRset's self-signature must verify with that key.
     *
     * @param  list<Ds>  $dsSet
     * @return list<Dnskey>|null
     */
    private function establishZoneKeys(string $zone, array $dsSet): ?array
    {
        $response = $this->resolver->query($zone, RecordType::DNSKEY, null, true, true);

        $keyRecords = $response->records;

        if ($keyRecords === []) {
            return null;
        }

        $keys = [];
        foreach ($keyRecords as $record) {
            if ($record->raw !== null) {
                $keys[] = Dnskey::fromRdata($record->raw);
            }
        }

        // A key tied to the parent DS is required to bootstrap trust in the set.
        $anchored = [];
        foreach ($keys as $key) {
            foreach ($dsSet as $ds) {
                if ($this->dsVerifier->matches($ds, $key, $zone)) {
                    $anchored[] = $key;
                    break;
                }
            }
        }

        if ($anchored === []) {
            return null; // no key is committed to by the parent — broken link
        }

        $rrsigs = $response->answerOfType(RecordType::RRSIG);

        if (! $this->verifyRrsetWithKeys(RecordType::DNSKEY, $keyRecords, $rrsigs, $anchored, $zone)) {
            return null; // the zone did not self-sign with an anchored key
        }

        return $keys;
    }

    /**
     * Obtain an authenticated DS RRset for `$child` from the `$parent` zone.
     *
     * @param  list<Dnskey>  $parentKeys
     * @return array{0: ValidationStatus, 1: list<Ds>}
     */
    private function authenticatedDs(string $child, string $parent, array $parentKeys): array
    {
        $response = $this->resolver->query($child, RecordType::DS, null, true, true);
        $dsRecords = $response->records;
        $rrsigs = $response->answerOfType(RecordType::RRSIG);

        if ($dsRecords !== []) {
            if (! $this->verifyRrset(RecordType::DS, $dsRecords, $rrsigs, $parentKeys, $parent)) {
                return [ValidationStatus::Bogus, []];
            }

            $dsSet = [];
            foreach ($dsRecords as $record) {
                if ($record->raw !== null) {
                    $dsSet[] = Ds::fromRdata($record->raw);
                }
            }

            return [ValidationStatus::Secure, $dsSet];
        }

        // No DS: only an authenticated NSEC/NSEC3 proof turns this into a genuine
        // (insecure) unsigned delegation; anything else is bogus.
        $nsec = $response->authorityOfType(RecordType::NSEC);
        $nsec3 = $response->authorityOfType(RecordType::NSEC3);
        $authorityRrsigs = $response->authorityOfType(RecordType::RRSIG);

        if ($this->denialAuthoritySigned($nsec, $nsec3, $authorityRrsigs, $parentKeys, $parent)
            && $this->denial->provesNoDs($child, $nsec, $nsec3)) {
            return [ValidationStatus::Insecure, []];
        }

        return [ValidationStatus::Bogus, []];
    }

    // --- signature helpers --------------------------------------------------

    /**
     * True if a single RRSIG over the RRset verifies with one of `$keys` whose key
     * tag matches. Deny-by-default: no matching, valid signature → false.
     *
     * @param  list<DnsRecord>  $rrset
     * @param  list<DnsRecord>  $rrsigRecords
     * @param  list<Dnskey>  $keys
     */
    private function verifyRrset(RecordType $type, array $rrset, array $rrsigRecords, array $keys, string $expectedSigner): bool
    {
        return $this->verifyRrsetWithKeys($type, $rrset, $rrsigRecords, $keys, $expectedSigner);
    }

    /**
     * @param  list<DnsRecord>  $rrset
     * @param  list<DnsRecord>  $rrsigRecords
     * @param  list<Dnskey>  $keys
     */
    private function verifyRrsetWithKeys(RecordType $type, array $rrset, array $rrsigRecords, array $keys, string $expectedSigner): bool
    {
        return $this->verifyingRrsig($type, $rrset, $rrsigRecords, $keys, $expectedSigner) !== null;
    }

    /**
     * The single RRSIG that verifies the RRset with one of `$keys`, or null when
     * none does. Exposes the winning signature so callers can inspect its label
     * count (wildcard detection). Deny-by-default: no valid signature → null.
     *
     * @param  list<DnsRecord>  $rrset
     * @param  list<DnsRecord>  $rrsigRecords
     * @param  list<Dnskey>  $keys
     */
    private function verifyingRrsig(RecordType $type, array $rrset, array $rrsigRecords, array $keys, string $expectedSigner): ?Rrsig
    {
        foreach ($rrsigRecords as $record) {
            if ($record->raw === null) {
                continue;
            }

            $rrsig = Rrsig::fromRdata($record->raw);

            if (! $rrsig->coversType($type)) {
                continue;
            }

            foreach ($keys as $key) {
                if ($key->keyTag() !== $rrsig->keyTag) {
                    continue;
                }

                if ($this->signatureVerifier->verify($rrsig, $type, $rrset, $key, $expectedSigner)) {
                    return $rrsig;
                }
            }
        }

        return null;
    }

    /**
     * Verify the wildcard "no closer match" proof (RFC 4035 §5.3.4): the authority
     * section must carry an authenticated, in-bailiwick NSEC/NSEC3 showing the
     * QNAME has no explicit match, so the wildcard expansion was legitimate.
     *
     * @param  list<Dnskey>  $keys
     */
    private function wildcardNoCloserMatch(string $host, int $encloserLabels, DnsResponse $response, array $keys, string $zone): bool
    {
        $nsec = $response->authorityOfType(RecordType::NSEC);
        $nsec3 = $response->authorityOfType(RecordType::NSEC3);
        $rrsigs = $response->authorityOfType(RecordType::RRSIG);

        // The proof RRsets must be validly signed by the (already in-bailiwick) zone.
        if (! $this->denialAuthoritySigned($nsec, $nsec3, $rrsigs, $keys, $zone)) {
            return false;
        }

        return $this->denial->nsecProvesNoCloserMatch($host, $nsec)
            || $this->denial->nsec3ProvesNoCloserMatch($host, $encloserLabels, $nsec3);
    }

    /**
     * Verify that every NSEC/NSEC3 RRset in a denial authority section is validly
     * signed by the zone's keys, grouping records into RRsets by owner name.
     *
     * @param  list<DnsRecord>  $nsec
     * @param  list<DnsRecord>  $nsec3
     * @param  list<DnsRecord>  $rrsigs
     * @param  list<Dnskey>  $keys
     */
    private function denialAuthoritySigned(array $nsec, array $nsec3, array $rrsigs, array $keys, string $zone): bool
    {
        if ($nsec === [] && $nsec3 === []) {
            return false;
        }

        return $this->rrsetsSigned(RecordType::NSEC, $nsec, $rrsigs, $keys, $zone)
            && $this->rrsetsSigned(RecordType::NSEC3, $nsec3, $rrsigs, $keys, $zone);
    }

    /**
     * @param  list<DnsRecord>  $records
     * @param  list<DnsRecord>  $rrsigs
     * @param  list<Dnskey>  $keys
     */
    private function rrsetsSigned(RecordType $type, array $records, array $rrsigs, array $keys, string $zone): bool
    {
        /** @var array<string, list<DnsRecord>> $byOwner */
        $byOwner = [];
        foreach ($records as $record) {
            $byOwner[strtolower($record->name)][] = $record;
        }

        foreach ($byOwner as $owner => $rrset) {
            $covering = array_values(array_filter(
                $rrsigs,
                static fn (DnsRecord $r): bool => strtolower($r->name) === $owner,
            ));

            if (! $this->verifyRrset($type, $rrset, $covering, $keys, $zone)) {
                return false;
            }
        }

        return true;
    }

    // --- name helpers -------------------------------------------------------

    /**
     * The signer name of the first RRSIG that covers `$type`.
     *
     * @param  list<DnsRecord>  $rrsigs
     */
    private function signerFor(array $rrsigs, RecordType $type): ?string
    {
        foreach ($rrsigs as $record) {
            if ($record->raw === null) {
                continue;
            }

            $rrsig = Rrsig::fromRdata($record->raw);

            if ($rrsig->coversType($type)) {
                return $this->normalize($rrsig->signerName);
            }
        }

        return null;
    }

    /**
     * @param  list<DnsRecord>  $rrsigs
     */
    private function anySigner(array $rrsigs): ?string
    {
        foreach ($rrsigs as $record) {
            if ($record->raw !== null) {
                return $this->normalize(Rrsig::fromRdata($record->raw)->signerName);
            }
        }

        return null;
    }

    /**
     * The zones between the root (exclusive) and `$zone` (inclusive), outermost
     * first — e.g. `cloudflare.com` → `['com', 'cloudflare.com']`.
     *
     * @return list<string>
     */
    private function descendants(string $zone): array
    {
        if ($zone === '') {
            return [];
        }

        $labels = explode('.', $zone);
        $chain = [];

        for ($i = count($labels) - 1; $i >= 0; $i--) {
            $chain[] = implode('.', array_slice($labels, $i));
        }

        return $chain;
    }

    /**
     * True when `$signer` is a label-aligned suffix of `$owner` — i.e. the signer
     * zone is `$owner` itself or one of its ancestors (RFC 4035 §5.3.1). Both are
     * normalized first; the comparison is on whole labels, so `evil.com` is NOT
     * in-bailiwick for `notevil.com`, and the root ('') is in-bailiwick for all.
     */
    private function inBailiwick(string $signer, string $owner): bool
    {
        $signer = $this->normalize($signer);
        $owner = $this->normalize($owner);

        if ($signer === '' || $signer === $owner) {
            return true;
        }

        return str_ends_with($owner, '.'.$signer);
    }

    private function labelCount(string $name): int
    {
        $name = $this->normalize($name);

        return $name === '' ? 0 : count(explode('.', $name));
    }

    private function normalize(string $name): string
    {
        return strtolower(rtrim($name, '.'));
    }

    private function label(string $zone): string
    {
        return $zone === '' ? 'root' : $zone;
    }
}
