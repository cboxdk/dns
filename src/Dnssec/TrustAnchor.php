<?php

declare(strict_types=1);

namespace Cbox\Dns\Dnssec;

use Cbox\Dns\Dnssec\Records\Ds;

/**
 * The DNS root trust anchors — the one piece of key material a validator must
 * hold out-of-band (published by IANA at data.iana.org/root-anchors). Both are
 * DS records (SHA-256, digest type 2) over the root KSK:
 *
 *   - KSK-2017, key tag 20326 (the current active root key).
 *   - KSK-2024, key tag 38696 (published for the next root key rollover).
 *
 * The validator anchors on these: the root DNSKEY RRset is trusted only once a
 * key in it matches one of these DS records and signs the set.
 */
class TrustAnchor
{
    private const string KSK_2017_DIGEST = 'E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D';

    private const string KSK_2024_DIGEST = '683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16';

    /**
     * The IANA root DS anchors.
     *
     * @return list<Ds>
     */
    public static function iana(): array
    {
        return [
            Ds::fromParts(20326, 8, 2, self::hex(self::KSK_2017_DIGEST)),
            Ds::fromParts(38696, 8, 2, self::hex(self::KSK_2024_DIGEST)),
        ];
    }

    private static function hex(string $hex): string
    {
        $bytes = hex2bin($hex);

        // The constants above are compile-time literals, so this never fails; the
        // guard keeps the return type honest for the static analyser.
        return $bytes === false ? '' : $bytes;
    }
}
