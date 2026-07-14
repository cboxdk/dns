<?php

declare(strict_types=1);

namespace Cbox\Dns\Dnssec\Support;

/**
 * Canonical DNS name ordering (RFC 4034 §6.1): names sort as if each is a
 * sequence of labels read right-to-left (most-significant label last), with
 * labels compared as left-justified, lowercased, unsigned octet strings. This is
 * the ordering NSEC/NSEC3 range checks depend on.
 */
class CanonicalName
{
    /**
     * @return list<string> labels of `$name`, lowercased, apex-first order intact
     *                      (i.e. left-to-right as written)
     */
    public static function labels(string $name): array
    {
        $name = strtolower(rtrim($name, '.'));

        return $name === '' ? [] : explode('.', $name);
    }

    /**
     * Compare two names in canonical order: negative if `$a` sorts before `$b`,
     * zero if equal, positive otherwise.
     */
    public static function compare(string $a, string $b): int
    {
        $left = array_reverse(self::labels($a));
        $right = array_reverse(self::labels($b));

        $count = min(count($left), count($right));

        for ($i = 0; $i < $count; $i++) {
            $cmp = strcmp($left[$i], $right[$i]);

            if ($cmp !== 0) {
                return $cmp < 0 ? -1 : 1;
            }
        }

        return count($left) <=> count($right);
    }

    /**
     * The longest common suffix (in whole labels) of two names — the deepest name
     * that is an ancestor of both. Used to derive the NSEC closest encloser.
     */
    public static function longestCommonSuffix(string $a, string $b): string
    {
        $left = array_reverse(self::labels($a));
        $right = array_reverse(self::labels($b));

        $common = [];
        $count = min(count($left), count($right));

        for ($i = 0; $i < $count; $i++) {
            if ($left[$i] !== $right[$i]) {
                break;
            }

            $common[] = $left[$i];
        }

        return implode('.', array_reverse($common));
    }

    /**
     * The parent (drop the leftmost label). The root's parent is the root.
     */
    public static function parent(string $name): string
    {
        $labels = self::labels($name);

        if (count($labels) <= 1) {
            return '';
        }

        return implode('.', array_slice($labels, 1));
    }
}
