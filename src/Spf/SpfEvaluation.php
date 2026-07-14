<?php

declare(strict_types=1);

namespace Cbox\Dns\Spf;

/**
 * The result of expanding an SPF policy (RFC 7208) — the sender-authorization tree
 * for a domain. It holds this record's own `ip4`/`ip6` mechanisms plus the nested
 * evaluations of every `include:` and the `redirect=` target, so you can read the
 * complete flattened endpoint list ({@see self::allIp4()} / {@see self::allIp6()})
 * or walk the tree for traceability.
 *
 * `exceededLookupLimit` reports the RFC 7208 §4.6.4 10-lookup cap being hit (a
 * `permerror` in SPF terms); `errors` collects loops, missing records, and lookup
 * failures encountered along the way.
 */
readonly class SpfEvaluation
{
    /**
     * @param  list<string>  $ip4  the `ip4:` (and expanded `a`/`mx` IPv4) prefixes of THIS record
     * @param  list<string>  $ip6  the `ip6:` (and expanded IPv6) prefixes of THIS record
     * @param  list<SpfEvaluation>  $includes  the nested evaluations of each `include:`
     * @param  list<string>  $errors
     */
    public function __construct(
        public string $domain,
        public ?string $record,
        public array $ip4,
        public array $ip6,
        public array $includes,
        public ?SpfEvaluation $redirect,
        public ?string $allQualifier,
        public int $lookups,
        public bool $exceededLookupLimit,
        public array $errors,
    ) {}

    /**
     * Whether an SPF record was found and the evaluation hit no hard error.
     */
    public function isValid(): bool
    {
        return $this->record !== null && $this->errors === [] && ! $this->exceededLookupLimit;
    }

    /**
     * The complete, de-duplicated IPv4 authorization list — this record's prefixes
     * plus every include's and the redirect's, recursively.
     *
     * @return list<string>
     */
    public function allIp4(): array
    {
        return $this->collect(static fn (SpfEvaluation $e): array => $e->ip4);
    }

    /**
     * The complete, de-duplicated IPv6 authorization list.
     *
     * @return list<string>
     */
    public function allIp6(): array
    {
        return $this->collect(static fn (SpfEvaluation $e): array => $e->ip6);
    }

    /**
     * Every domain named in the evaluation tree (this one, each include, redirect).
     *
     * @return list<string>
     */
    public function domains(): array
    {
        $domains = [$this->domain];

        foreach ($this->includes as $include) {
            $domains = array_merge($domains, $include->domains());
        }

        if ($this->redirect !== null) {
            $domains = array_merge($domains, $this->redirect->domains());
        }

        return array_values(array_unique($domains));
    }

    /**
     * @param  callable(SpfEvaluation): list<string>  $pick
     * @return list<string>
     */
    private function collect(callable $pick): array
    {
        $values = $pick($this);

        foreach ($this->includes as $include) {
            $values = array_merge($values, $include->collect($pick));
        }

        if ($this->redirect !== null) {
            $values = array_merge($values, $this->redirect->collect($pick));
        }

        return array_values(array_unique($values));
    }
}
