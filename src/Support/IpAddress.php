<?php

declare(strict_types=1);

namespace Cbox\Dns\Support;

/**
 * Small IP helpers the diagnostics checks share: telling an IP literal from a
 * hostname, deciding whether an address is a usable public one, and building the
 * reverse-DNS pointer name for a PTR lookup. Pure string/`filter_var` work — no
 * network, no state.
 */
class IpAddress
{
    public static function isIp(string $value): bool
    {
        return filter_var($value, FILTER_VALIDATE_IP) !== false;
    }

    /**
     * True only for a globally-routable unicast address: rejects RFC1918 private
     * ranges, loopback, link-local, and other reserved space (via the NO_PRIV_RANGE
     * and NO_RES_RANGE flags), for both IPv4 and IPv6.
     *
     * IPv4-mapped/-compatible and 6to4/NAT64 IPv6 forms are unwrapped and the
     * embedded IPv4 re-checked, so `::ffff:169.254.169.254` (or a 6to4 wrapper for a
     * private v4) cannot smuggle a reserved address past the v6 filter.
     */
    public static function isPublic(string $value): bool
    {
        $embedded = self::embeddedIpv4($value);

        if ($embedded !== null && ! self::isPublic($embedded)) {
            return false;
        }

        // RFC 6598 CGNAT shared address space (100.64.0.0/10) is not covered by
        // PHP's reserved-range flags, yet is internal in carrier/NAT deployments —
        // reject it explicitly so it cannot be an SSRF target.
        if (self::inCidr($value, '100.64.0.0', 10)) {
            return false;
        }

        return filter_var(
            $value,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE,
        ) !== false;
    }

    /**
     * Whether an IPv4 address falls within a CIDR block.
     */
    private static function inCidr(string $value, string $network, int $prefix): bool
    {
        $ip = ip2long($value);
        $net = ip2long($network);

        if ($ip === false || $net === false) {
            return false; // not IPv4
        }

        $mask = $prefix === 0 ? 0 : (-1 << (32 - $prefix)) & 0xFFFFFFFF;

        return ($ip & $mask) === ($net & $mask);
    }

    /**
     * The IPv4 address embedded in an IPv4-mapped (`::ffff:a.b.c.d`),
     * IPv4-compatible (`::a.b.c.d`), 6to4 (`2002:aabb:ccdd::`), or NAT64
     * (`64:ff9b::a.b.c.d`) IPv6 address, or null when there is none.
     */
    private static function embeddedIpv4(string $value): ?string
    {
        $packed = @inet_pton($value);

        if ($packed === false || strlen($packed) !== 16) {
            return null;
        }

        // ::ffff:0:0/96 (mapped), ::/96 (compatible), 64:ff9b::/96 (NAT64) — the
        // embedded IPv4 is the final four octets.
        $mappedPrefix = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff";
        $compatPrefix = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        $nat64Prefix = "\x00\x64\xff\x9b\x00\x00\x00\x00\x00\x00\x00\x00";
        $prefix = substr($packed, 0, 12);

        if ($prefix === $mappedPrefix || $prefix === $compatPrefix || $prefix === $nat64Prefix) {
            $v4 = inet_ntop(substr($packed, 12));

            return $v4 === false ? null : $v4;
        }

        // 6to4 (2002::/16): the embedded IPv4 is octets 2-5.
        if (substr($packed, 0, 2) === "\x20\x02") {
            $v4 = inet_ntop(substr($packed, 2, 4));

            return $v4 === false ? null : $v4;
        }

        return null;
    }

    /**
     * The reverse-DNS pointer name for an IP (`in-addr.arpa` for IPv4, nibble
     * `ip6.arpa` for IPv6), or null if `$value` is not an IP.
     */
    public static function reversePointer(string $value): ?string
    {
        $packed = @inet_pton($value);

        if ($packed === false) {
            return null;
        }

        return strlen($packed) === 4
            ? self::ipv4Pointer($packed)
            : self::ipv6Pointer($packed);
    }

    private static function ipv4Pointer(string $packed): string
    {
        $octets = array_map(
            static fn (string $octet): string => (string) ord($octet),
            str_split($packed),
        );

        return implode('.', array_reverse($octets)).'.in-addr.arpa';
    }

    private static function ipv6Pointer(string $packed): string
    {
        $nibbles = str_split(bin2hex($packed));

        return implode('.', array_reverse($nibbles)).'.ip6.arpa';
    }
}
