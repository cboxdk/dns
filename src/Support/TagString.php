<?php

declare(strict_types=1);

namespace Cbox\Dns\Support;

/**
 * Parses the `tag=value; tag=value` grammar shared by DKIM (RFC 6376) and DMARC
 * (RFC 7489) TXT records into a keyed map, trimming whitespace and lower-casing the
 * tag names. Later duplicate tags overwrite earlier ones.
 */
final class TagString
{
    /**
     * @return array<string, string>
     */
    public static function parse(string $value): array
    {
        $tags = [];

        foreach (explode(';', $value) as $pair) {
            if (! str_contains($pair, '=')) {
                continue;
            }

            [$key, $val] = explode('=', $pair, 2);
            $key = strtolower(trim($key));

            if ($key !== '') {
                $tags[$key] = trim($val);
            }
        }

        return $tags;
    }
}
