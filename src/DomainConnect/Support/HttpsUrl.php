<?php

declare(strict_types=1);

namespace Cbox\Dns\DomainConnect\Support;

/**
 * The one definition of a "plain https URL" for the Domain Connect module: a URL
 * that came from data others control (a `_domainconnect` TXT value, a provider's
 * settings document) and is about to be fetched or handed to a browser.
 */
class HttpsUrl
{
    /**
     * Whether the URL is https with a hostname or (bracketed) IP literal host and
     * no userinfo, query or fragment.
     */
    public static function isPlain(string $url): bool
    {
        return self::host($url) !== null;
    }

    /**
     * The host of a plain https URL (see {@see self::isPlain()}), brackets of an
     * IPv6 literal stripped; null when the URL is not plain.
     */
    public static function host(string $url): ?string
    {
        $parts = parse_url($url);

        if (! is_array($parts)
            || strtolower($parts['scheme'] ?? '') !== 'https'
            || isset($parts['user']) || isset($parts['pass']) || isset($parts['query']) || isset($parts['fragment'])
        ) {
            return null;
        }

        $host = $parts['host'] ?? '';

        if (preg_match('/^\[(.+)\]$/', $host, $m) === 1) {
            return filter_var($m[1], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false ? $m[1] : null;
        }

        return preg_match('/^[A-Za-z0-9.-]+$/', $host) === 1 ? $host : null;
    }

    /**
     * A provider base URL (`urlSyncUX`, `urlAPI`) ready for `/v2/...` to be
     * appended: trailing slashes removed, and one trailing `/v2` dropped so a
     * provider that publishes its base with the version does not get `/v2/v2`.
     */
    public static function base(string $url): string
    {
        $url = rtrim($url, '/');

        return strcasecmp(substr($url, -3), '/v2') === 0 ? substr($url, 0, -3) : $url;
    }
}
