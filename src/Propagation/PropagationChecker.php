<?php

declare(strict_types=1);

namespace Cbox\Dns\Propagation;

use Cbox\Dns\Contracts\ConcurrentResolver;
use Cbox\Dns\Contracts\Resolver;
use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Exceptions\DnsException;
use Cbox\Dns\Resolvers\AuthoritativeResolver;
use Cbox\Dns\Resolvers\SocketResolver;
use Cbox\Dns\Testing\FakeResolver;
use Cbox\Dns\ValueObjects\QueryRequest;

/**
 * intoDNS/whatsmydns-style propagation check: compares the authoritative record
 * set for a host against what a panel of public recursive resolvers currently
 * return, so you can tell a misconfiguration apart from an in-flight TTL rollover.
 *
 * Both the public panel and the authoritative view resolve through injected
 * collaborators, so {@see FakeResolver} drives the whole check
 * with per-nameserver stubs and no network. When the public resolver implements
 * {@see ConcurrentResolver} (the default {@see SocketResolver}
 * does), the whole panel is polled concurrently under one timeout budget rather
 * than one server at a time.
 */
class PropagationChecker
{
    /** @var list<string> */
    private readonly array $publicNameservers;

    /**
     * @param  list<string>|null  $publicNameservers  overrides the lean default
     *                                                panel; null uses
     *                                                {@see self::defaultNameservers()}
     */
    public function __construct(
        private readonly Resolver $publicResolver,
        private readonly AuthoritativeResolver $authoritative,
        ?array $publicNameservers = null,
    ) {
        $this->publicNameservers = $publicNameservers ?? self::defaultNameservers();
    }

    /**
     * The lean default panel — one IP per major operator — derived from the named
     * {@see PublicResolvers} registry so the two never drift apart.
     *
     * @return list<string>
     */
    public static function defaultNameservers(): array
    {
        return array_map(static fn (PublicResolver $r): string => $r->ip, PublicResolvers::default());
    }

    /**
     * The default lean check: compare the authoritative set against this checker's
     * bare IP panel (no provider labels).
     */
    public function check(string $host, RecordType $type, string $zone): PropagationReport
    {
        $probes = array_map(
            static fn (string $ip): array => ['ip' => $ip, 'label' => null],
            $this->publicNameservers,
        );

        return $this->report($host, $type, $zone, $probes);
    }

    /**
     * The wider, named check: poll the FULL public-resolver registry
     * ({@see PublicResolvers::all()}) and label each {@see ResolverResult} with its
     * provider, so a report reads "Google Public DNS ✓ / Cloudflare ✓ / Quad9
     * pending" rather than bare IPs.
     *
     * Honest scope: this queries many public resolvers FROM THIS HOST — a
     * cache-diversity signal across independent operators, NOT true global
     * geographic propagation. Every major provider is anycast, so from one host you
     * reach the nearest PoP and sample operators, not locations. The reliable
     * propagation signal is still the authoritative-vs-recursive diff this report
     * carries. Geo-distributed vantage points (regional DoH probes) are a documented
     * roadmap item, not a claim made here.
     */
    public function checkAcrossProviders(string $host, RecordType $type, string $zone): PropagationReport
    {
        $probes = array_map(
            static fn (PublicResolver $resolver): array => ['ip' => $resolver->ip, 'label' => $resolver->label],
            PublicResolvers::all(),
        );

        return $this->report($host, $type, $zone, $probes);
    }

    /**
     * Compare the authoritative set against a list of labelled probes.
     *
     * @param  list<array{ip: string, label: string|null}>  $probes
     */
    private function report(string $host, RecordType $type, string $zone, array $probes): PropagationReport
    {
        $authoritativeValues = $this->normalize($this->authoritativeValues($host, $type, $zone));

        $publicValues = $this->publicValues($host, $type, $probes);

        $results = [];
        $allAgree = true;

        foreach ($probes as $i => $probe) {
            $values = $this->normalize($publicValues[$i]);
            $agrees = $authoritativeValues !== [] && $values === $authoritativeValues;
            $allAgree = $allAgree && $agrees;

            $results[] = new ResolverResult($probe['ip'], $values, $agrees, $probe['label']);
        }

        return new PropagationReport($authoritativeValues, $results, $this->status($authoritativeValues, $allAgree));
    }

    /**
     * The public panel's answers, one per probe (index-aligned). Uses the
     * concurrent path when the resolver supports it, else a sequential fallback.
     *
     * @param  list<array{ip: string, label: string|null}>  $probes
     * @return list<list<string>>
     */
    private function publicValues(string $host, RecordType $type, array $probes): array
    {
        if ($this->publicResolver instanceof ConcurrentResolver) {
            $requests = array_map(
                static fn (array $probe): QueryRequest => new QueryRequest($host, $type, $probe['ip']),
                $probes,
            );

            return array_map(
                static fn ($response): array => $response->values(),
                $this->publicResolver->queryConcurrently($requests),
            );
        }

        return array_map(
            fn (array $probe): array => $this->publicValuesFor($host, $type, $probe['ip']),
            $probes,
        );
    }

    /**
     * @param  list<string>  $authoritativeValues
     */
    private function status(array $authoritativeValues, bool $allAgree): PropagationStatus
    {
        if ($authoritativeValues === []) {
            return PropagationStatus::Misconfigured;
        }

        return $allAgree ? PropagationStatus::Propagated : PropagationStatus::Pending;
    }

    /**
     * @return list<string>
     */
    private function authoritativeValues(string $host, RecordType $type, string $zone): array
    {
        try {
            return $this->authoritative->query($host, $type, $zone)->values();
        } catch (DnsException) {
            return [];
        }
    }

    /**
     * @return list<string>
     */
    private function publicValuesFor(string $host, RecordType $type, string $nameserver): array
    {
        try {
            return $this->publicResolver->query($host, $type, $nameserver)->values();
        } catch (DnsException) {
            return [];
        }
    }

    /**
     * A stable, order-independent comparison key: de-duplicated and sorted.
     *
     * @param  list<string>  $values
     * @return list<string>
     */
    private function normalize(array $values): array
    {
        $unique = array_values(array_unique($values));
        sort($unique);

        return $unique;
    }
}
