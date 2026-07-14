<?php

declare(strict_types=1);

namespace Cbox\Dns\Diagnostics;

use Cbox\Dns\Contracts\Resolver;
use Cbox\Dns\Dnssec\DnssecValidator;
use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Exceptions\DnsException;
use Cbox\Dns\Propagation\PropagationChecker;
use Cbox\Dns\Resolvers\AuthoritativeResolver;
use Cbox\Dns\Testing\FakeResolver;

/**
 * The shared state a diagnostic run threads through every {@see Contracts\Check}:
 * the target `domain` (the apex zone under test) and the injected collaborators the
 * checks resolve through — a recursive {@see Resolver}, the cache-bypassing
 * {@see AuthoritativeResolver}, the {@see DnssecValidator}, and the
 * {@see PropagationChecker}. Because every check reaches DNS only through these,
 * a {@see FakeResolver} drives the entire engine offline.
 *
 * The `domain` is normalised to a bare, lower-case zone name (no trailing dot).
 */
final readonly class DiagnosticContext
{
    public string $domain;

    public function __construct(
        string $domain,
        public Resolver $resolver,
        public AuthoritativeResolver $authoritative,
        public DnssecValidator $dnssec,
        public PropagationChecker $propagation,
    ) {
        $this->domain = strtolower(trim(trim($domain), ".\t\n\r "));
    }

    /**
     * The domain's delegated nameserver hostnames, read recursively. A resolution
     * failure surfaces as an empty list, never an exception — a check decides what
     * that means.
     *
     * @return list<string>
     */
    public function nameservers(): array
    {
        return $this->addressesOfType($this->domain, RecordType::NS);
    }

    /**
     * A host's public addresses (A then AAAA), read recursively.
     *
     * @return list<string>
     */
    public function addresses(string $host): array
    {
        return [
            ...$this->addressesOfType($host, RecordType::A),
            ...$this->addressesOfType($host, RecordType::AAAA),
        ];
    }

    /**
     * @return list<string>
     */
    private function addressesOfType(string $host, RecordType $type): array
    {
        try {
            return array_map(
                static fn (string $value): string => rtrim($value, '.'),
                $this->resolver->query($host, $type)->values(),
            );
        } catch (DnsException) {
            return [];
        }
    }
}
