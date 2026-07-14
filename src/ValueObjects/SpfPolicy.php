<?php

declare(strict_types=1);

namespace Cbox\Dns\ValueObjects;

/**
 * A parsed SPF policy (RFC 7208) from a `v=spf1 …` TXT record: the ordered
 * mechanisms, an optional `redirect=` modifier, an optional `exp=` explanation, and
 * the trailing `all` qualifier (the default result when nothing else matches).
 */
readonly class SpfPolicy
{
    /**
     * @param  list<SpfMechanism>  $mechanisms
     */
    public function __construct(
        public array $mechanisms,
        public ?string $allQualifier = null,
        public ?string $redirect = null,
        public ?string $explanation = null,
    ) {}

    /**
     * Parse a TXT string as SPF, or null if it is not an SPF record (`v=spf1`).
     */
    public static function parse(string $txt): ?self
    {
        $txt = trim($txt);

        if (! preg_match('/^v=spf1(\s|$)/i', $txt)) {
            return null;
        }

        $terms = preg_split('/\s+/', $txt) ?: [];
        array_shift($terms); // drop the version token

        $mechanisms = [];
        $allQualifier = null;
        $redirect = null;
        $explanation = null;

        foreach ($terms as $term) {
            if ($term === '') {
                continue;
            }

            if (str_starts_with(strtolower($term), 'redirect=')) {
                $redirect = substr($term, 9);

                continue;
            }

            if (str_starts_with(strtolower($term), 'exp=')) {
                $explanation = substr($term, 4);

                continue;
            }

            $qualifier = '+';
            if (in_array($term[0], ['+', '-', '~', '?'], true)) {
                $qualifier = $term[0];
                $term = substr($term, 1);
            }

            $parts = explode(':', $term, 2);
            $name = strtolower($parts[0]);
            $value = $parts[1] ?? null;

            if ($name === '') {
                continue; // a bare qualifier with no mechanism name is not a term
            }

            if ($name === 'all') {
                $allQualifier = $qualifier;
            }

            $mechanisms[] = new SpfMechanism($qualifier, $name, $value);
        }

        return new self($mechanisms, $allQualifier, $redirect, $explanation);
    }
}
