<?php

declare(strict_types=1);

namespace Cbox\Dns\Dnssec;

use Cbox\Dns\Dnssec\Records\Nsec;
use Cbox\Dns\Dnssec\Records\Nsec3;
use Cbox\Dns\Dnssec\Support\Base32Hex;
use Cbox\Dns\Dnssec\Support\CanonicalName;
use Cbox\Dns\Dnssec\Support\WireName;
use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\ValueObjects\DnsRecord;

/**
 * Authenticated denial of existence (RFC 4034 §4, RFC 5155). Given the
 * NSEC/NSEC3 records from an ALREADY-VALIDATED authority section, this proves —
 * from the canonical name/hash ordering alone — that a name or a name+type does
 * not exist. It performs NO signature checks itself; the caller must have
 * verified the RRSIGs over these records first, otherwise the proof is worthless.
 *
 * Deny-by-default: a proof returns true only when the covering/matching ranges
 * conclusively establish absence. Anything short of that is false.
 */
final class DenialOfExistence
{
    // --- NSEC ---------------------------------------------------------------

    /**
     * Prove `$qname` has no record of `$type` (a NODATA answer): a matching NSEC
     * exists at `$qname` whose bitmap lists neither `$type` nor CNAME.
     *
     * @param  list<DnsRecord>  $nsecRecords
     */
    public function nsecProvesNoData(string $qname, RecordType $type, array $nsecRecords): bool
    {
        foreach ($this->nsecs($nsecRecords) as [$owner, $nsec]) {
            if (CanonicalName::compare($owner, $qname) === 0
                && ! $nsec->hasType($type)
                && ! $nsec->hasType(RecordType::CNAME)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Prove `$qname` does not exist at all (a name error): some NSEC covers the
     * name, AND some NSEC covers the wildcard at the derived closest encloser —
     * so no wildcard could have synthesised it either (RFC 4035 §5.4).
     *
     * @param  list<DnsRecord>  $nsecRecords
     */
    public function nsecProvesNxDomain(string $qname, array $nsecRecords): bool
    {
        $nsecs = $this->nsecs($nsecRecords);

        $closestEncloser = null;

        foreach ($nsecs as [$owner, $nsec]) {
            if ($this->nsecCovers($owner, $nsec->nextDomainName, $qname)) {
                $closestEncloser = $this->deriveEncloser($qname, $owner, $nsec->nextDomainName);
                break;
            }
        }

        if ($closestEncloser === null) {
            return false; // qname itself never proven absent
        }

        $wildcard = $closestEncloser === '' ? '*' : '*.'.$closestEncloser;

        foreach ($nsecs as [$owner, $nsec]) {
            if ($this->nsecCovers($owner, $nsec->nextDomainName, $wildcard)) {
                return true;
            }
        }

        return false;
    }

    // --- NSEC3 --------------------------------------------------------------

    /**
     * Prove `$qname` has no record of `$type` (NODATA) via NSEC3: a matching
     * NSEC3 exists whose bitmap lists neither `$type` nor CNAME.
     *
     * @param  list<DnsRecord>  $nsec3Records
     */
    public function nsec3ProvesNoData(string $qname, RecordType $type, array $nsec3Records): bool
    {
        foreach ($this->nsec3s($nsec3Records) as [$ownerHash, $nsec3]) {
            $hash = $this->nsec3Hash($qname, $nsec3->iterations, $nsec3->salt);

            if (hash_equals($ownerHash, $hash)
                && ! $nsec3->hasType($type)
                && ! $nsec3->hasType(RecordType::CNAME)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Prove `$qname` does not exist via the NSEC3 closest-encloser proof
     * (RFC 5155 §8.4): a matching NSEC3 for the closest encloser, a covering
     * NSEC3 for the next-closer name, and a covering NSEC3 for the wildcard.
     *
     * @param  list<DnsRecord>  $nsec3Records
     */
    public function nsec3ProvesNxDomain(string $qname, array $nsec3Records): bool
    {
        $nsec3s = $this->nsec3s($nsec3Records);

        if ($nsec3s === []) {
            return false;
        }

        [$iterations, $salt] = [$nsec3s[0][1]->iterations, $nsec3s[0][1]->salt];

        $ancestors = $this->ancestors($qname);

        // Closest encloser: the longest proper ancestor of qname with a matching
        // NSEC3. Index 0 is qname itself (absent), so start at its parent.
        for ($i = 1; $i < count($ancestors); $i++) {
            $encloser = $ancestors[$i];

            if (! $this->nsec3Matches($nsec3s, $encloser, $iterations, $salt)) {
                continue;
            }

            $nextCloser = $ancestors[$i - 1];
            $wildcard = $encloser === '' ? '*' : '*.'.$encloser;

            return $this->nsec3Covers($nsec3s, $nextCloser, $iterations, $salt)
                && $this->nsec3Covers($nsec3s, $wildcard, $iterations, $salt);
        }

        return false;
    }

    /**
     * Prove there is no DS for `$child` at the parent — an insecure delegation.
     * NSEC: a matching NSEC lacking the DS bit (and it is a delegation, not the
     * apex, so NS present without SOA). NSEC3: a matching NSEC3 lacking DS, or a
     * covering NSEC3 with the Opt-Out flag set (RFC 5155 §6).
     *
     * @param  list<DnsRecord>  $nsecRecords
     * @param  list<DnsRecord>  $nsec3Records
     */
    public function provesNoDs(string $child, array $nsecRecords, array $nsec3Records): bool
    {
        foreach ($this->nsecs($nsecRecords) as [$owner, $nsec]) {
            if (CanonicalName::compare($owner, $child) === 0
                && ! $nsec->hasType(RecordType::DS)
                && $nsec->hasType(RecordType::NS)
                && ! $nsec->hasType(RecordType::SOA)) {
                return true;
            }
        }

        $nsec3s = $this->nsec3s($nsec3Records);

        foreach ($nsec3s as [$ownerHash, $nsec3]) {
            $hash = $this->nsec3Hash($child, $nsec3->iterations, $nsec3->salt);

            // Matching NSEC3 with no DS bit: provably no DS at an existing name.
            if (hash_equals($ownerHash, $hash)
                && ! $nsec3->hasType(RecordType::DS)
                && ! $nsec3->hasType(RecordType::SOA)) {
                return true;
            }

            // Opt-out covering NSEC3: the delegation may be unsigned.
            if ($nsec3->isOptOut()
                && $this->nsec3CoversHash($ownerHash, $nsec3->nextHashedOwner, $hash)) {
                return true;
            }
        }

        return false;
    }

    /**
     * The NSEC3 hash of a name (RFC 5155 §5): iterated SHA-1 over the canonical
     * wire name concatenated with the salt.
     */
    public function nsec3Hash(string $name, int $iterations, string $salt): string
    {
        $hash = hash('sha1', WireName::canonical($name).$salt, binary: true);

        for ($i = 0; $i < $iterations; $i++) {
            $hash = hash('sha1', $hash.$salt, binary: true);
        }

        return $hash;
    }

    // --- internals ----------------------------------------------------------

    private function nsecCovers(string $owner, string $next, string $qname): bool
    {
        $ownerVsQ = CanonicalName::compare($owner, $qname);
        $qVsNext = CanonicalName::compare($qname, $next);

        if (CanonicalName::compare($owner, $next) < 0) {
            return $ownerVsQ < 0 && $qVsNext < 0; // normal interval
        }

        // The last NSEC wraps past the apex: next <= owner.
        return $ownerVsQ < 0 || $qVsNext < 0;
    }

    private function deriveEncloser(string $qname, string $owner, string $next): string
    {
        $fromOwner = CanonicalName::longestCommonSuffix($qname, $owner);
        $fromNext = CanonicalName::longestCommonSuffix($qname, $next);

        return strlen($fromOwner) >= strlen($fromNext) ? $fromOwner : $fromNext;
    }

    /**
     * @param  list<array{0: string, 1: Nsec3}>  $nsec3s
     */
    private function nsec3Matches(array $nsec3s, string $name, int $iterations, string $salt): bool
    {
        $hash = $this->nsec3Hash($name, $iterations, $salt);

        foreach ($nsec3s as [$ownerHash]) {
            if (hash_equals($ownerHash, $hash)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param  list<array{0: string, 1: Nsec3}>  $nsec3s
     */
    private function nsec3Covers(array $nsec3s, string $name, int $iterations, string $salt): bool
    {
        $hash = $this->nsec3Hash($name, $iterations, $salt);

        foreach ($nsec3s as [$ownerHash, $nsec3]) {
            if ($this->nsec3CoversHash($ownerHash, $nsec3->nextHashedOwner, $hash)) {
                return true;
            }
        }

        return false;
    }

    private function nsec3CoversHash(string $ownerHash, string $nextHash, string $hash): bool
    {
        $ownerVsH = strcmp($ownerHash, $hash);
        $hVsNext = strcmp($hash, $nextHash);

        if (strcmp($ownerHash, $nextHash) < 0) {
            return $ownerVsH < 0 && $hVsNext < 0;
        }

        // Wrap at the last NSEC3 in the ordered chain.
        return $ownerVsH < 0 || $hVsNext < 0;
    }

    /**
     * @return list<string> qname, then each ancestor up to the root ('')
     */
    private function ancestors(string $qname): array
    {
        $names = [];
        $current = strtolower(rtrim($qname, '.'));

        while (true) {
            $names[] = $current;

            if ($current === '') {
                break;
            }

            $current = CanonicalName::parent($current);
        }

        return $names;
    }

    /**
     * @param  list<DnsRecord>  $records
     * @return list<array{0: string, 1: Nsec}>
     */
    private function nsecs(array $records): array
    {
        $out = [];

        foreach ($records as $record) {
            if ($record->type === RecordType::NSEC && $record->raw !== null) {
                $out[] = [$record->name, Nsec::fromRdata($record->raw)];
            }
        }

        return $out;
    }

    /**
     * @param  list<DnsRecord>  $records
     * @return list<array{0: string, 1: Nsec3}>
     */
    private function nsec3s(array $records): array
    {
        $out = [];

        foreach ($records as $record) {
            if ($record->type !== RecordType::NSEC3 || $record->raw === null) {
                continue;
            }

            $labels = CanonicalName::labels($record->name);

            if ($labels === []) {
                continue;
            }

            $out[] = [Base32Hex::decode($labels[0]), Nsec3::fromRdata($record->raw)];
        }

        return $out;
    }
}
