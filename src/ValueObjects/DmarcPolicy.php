<?php

declare(strict_types=1);

namespace Cbox\Dns\ValueObjects;

use Cbox\Dns\Support\TagString;

/**
 * A parsed DMARC policy (RFC 7489) from a `_dmarc` TXT record: the domain policy
 * (`none` / `quarantine` / `reject`), an optional subdomain policy, the sampling
 * percentage, the aggregate/forensic report URIs, and the alignment/failure options.
 */
readonly class DmarcPolicy
{
    /**
     * @param  list<string>  $aggregateReports  the `rua=` mailto/URI list
     * @param  list<string>  $forensicReports  the `ruf=` mailto/URI list
     */
    public function __construct(
        public string $policy,
        public ?string $subdomainPolicy = null,
        public int $percentage = 100,
        public array $aggregateReports = [],
        public array $forensicReports = [],
        public string $adkim = 'r',
        public string $aspf = 'r',
        public ?string $failureOptions = null,
        public ?int $reportInterval = null,
    ) {}

    /**
     * The policy that applies to a subdomain — the explicit `sp=` if present, else
     * the domain policy.
     */
    public function effectiveSubdomainPolicy(): string
    {
        return $this->subdomainPolicy ?? $this->policy;
    }

    /**
     * Parse a TXT string as a DMARC policy, or null if it is not one (`v=DMARC1`).
     */
    public static function parse(string $txt): ?self
    {
        $tags = TagString::parse($txt);

        if (! isset($tags['v']) || strcasecmp($tags['v'], 'DMARC1') !== 0 || ! isset($tags['p'])) {
            return null;
        }

        $percentage = isset($tags['pct']) && ctype_digit($tags['pct']) ? (int) $tags['pct'] : 100;
        $interval = isset($tags['ri']) && ctype_digit($tags['ri']) ? (int) $tags['ri'] : null;

        return new self(
            strtolower($tags['p']),
            isset($tags['sp']) ? strtolower($tags['sp']) : null,
            $percentage,
            self::uriList($tags['rua'] ?? null),
            self::uriList($tags['ruf'] ?? null),
            strtolower($tags['adkim'] ?? 'r'),
            strtolower($tags['aspf'] ?? 'r'),
            $tags['fo'] ?? null,
            $interval,
        );
    }

    /**
     * @return list<string>
     */
    private static function uriList(?string $value): array
    {
        if ($value === null || trim($value) === '') {
            return [];
        }

        return array_values(array_filter(array_map('trim', explode(',', $value)), static fn (string $v): bool => $v !== ''));
    }
}
