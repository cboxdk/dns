<?php

declare(strict_types=1);

namespace Cbox\Dns\Diagnostics\Support;

/**
 * Small IP helpers the diagnostics checks share: telling an IP literal from a
 * hostname, deciding whether an address is a usable public one, and building the
 * reverse-DNS pointer name for a PTR lookup. Pure string/`filter_var` work — no
 * network, no state.
 */
final class IpAddress
{
    public static function isIp(string $value): bool
    {
        return filter_var($value, FILTER_VALIDATE_IP) !== false;
    }

    /**
     * True only for a globally-routable unicast address: rejects RFC1918 private
     * ranges, loopback, link-local, and other reserved space (via the NO_PRIV_RANGE
     * and NO_RES_RANGE flags), for both IPv4 and IPv6.
     */
    public static function isPublic(string $value): bool
    {
        return filter_var(
            $value,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE,
        ) !== false;
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
