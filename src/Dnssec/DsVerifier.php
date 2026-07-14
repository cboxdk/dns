<?php

declare(strict_types=1);

namespace Cbox\Dns\Dnssec;

use Cbox\Dns\Dnssec\Enums\DigestType;
use Cbox\Dns\Dnssec\Records\Dnskey;
use Cbox\Dns\Dnssec\Records\Ds;
use Cbox\Dns\Dnssec\Support\WireName;

/**
 * Verifies the parent→child delegation link (RFC 4034 §5.1.4): the DS digest is
 * `hash( canonical-owner-name ‖ DNSKEY-RDATA )`. A match — together with equal
 * key tag and algorithm — proves the parent commits to exactly this child KSK.
 *
 * Deny-by-default: an unsupported digest type (SHA-1, GOST), a key-tag or
 * algorithm mismatch, or a digest that does not compare equal all return false.
 * The digest comparison is constant-time.
 */
class DsVerifier
{
    public function matches(Ds $ds, Dnskey $key, string $ownerName): bool
    {
        $digestType = DigestType::fromCode($ds->digestType);

        if ($digestType === null) {
            return false; // unsupported / deprecated digest algorithm → deny
        }

        if ($key->algorithm !== $ds->algorithm) {
            return false;
        }

        if ($key->keyTag() !== $ds->keyTag) {
            return false;
        }

        $computed = hash(
            $digestType->hashAlgo(),
            WireName::canonical($ownerName).$key->rdata,
            binary: true,
        );

        return hash_equals($ds->digest, $computed);
    }
}
