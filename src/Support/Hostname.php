<?php

declare(strict_types=1);

namespace Cbox\Dns\Support;

use Cbox\Dns\Exceptions\InvalidName;

/**
 * Host-name normalization at the wire boundary. The one job that matters here is
 * IDN → A-label conversion: a Unicode name like `blåbærgrød.dk` must be punycoded
 * to `xn--blbrgrd-fxak7p.dk` before it goes on the wire, or the query asks for the
 * wrong name entirely.
 *
 * Conversion uses `ext-intl` (`idn_to_ascii`) when it is available. To keep the
 * library's zero-dependency stance, `ext-intl` is NOT a hard requirement: an
 * already-ASCII name passes through untouched without it, and only a genuinely
 * non-ASCII name on a build lacking `ext-intl` is refused (rather than silently
 * queried as mojibake).
 */
final class Hostname
{
    /**
     * Convert a host to its ASCII (A-label / punycode) form, trailing dot stripped.
     * ASCII input is returned unchanged; non-ASCII input requires `ext-intl`.
     *
     * @throws InvalidName when a non-ASCII name cannot be converted
     */
    public static function toAscii(string $host): string
    {
        $host = rtrim(trim($host), '.');

        if ($host === '' || self::isAscii($host)) {
            return $host;
        }

        if (! function_exists('idn_to_ascii')) {
            throw InvalidName::make($host, 'a non-ASCII (IDN) name requires ext-intl for punycode conversion');
        }

        $ascii = idn_to_ascii($host, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);

        if ($ascii === false) {
            throw InvalidName::make($host, 'the name could not be converted to punycode');
        }

        return rtrim($ascii, '.');
    }

    private static function isAscii(string $value): bool
    {
        return $value === '' || ! preg_match('/[^\x00-\x7F]/', $value);
    }
}
