<?php

declare(strict_types=1);

namespace Cbox\Dns\Propagation;

use Cbox\Dns\Contracts\Resolver;
use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Exceptions\DnsException;
use Cbox\Dns\Resolvers\AuthoritativeResolver;
use Cbox\Dns\Testing\FakeResolver;

/**
 * intoDNS/whatsmydns-style propagation check: compares the authoritative record
 * set for a host against what a panel of public recursive resolvers currently
 * return, so you can tell a misconfiguration apart from an in-flight TTL rollover.
 *
 * Both the public panel and the authoritative view resolve through injected
 * collaborators, so {@see FakeResolver} drives the whole check
 * with per-nameserver stubs and no network.
 */
final class PropagationChecker
{
    /**
     * The default public recursive resolvers polled: Google, Cloudflare, Quad9, OpenDNS.
     *
     * @var list<string>
     */
    public const array DEFAULT_NAMESERVERS = [
        '8.8.8.8',
        '8.8.4.4',
        '1.1.1.1',
        '1.0.0.1',
        '9.9.9.9',
        '208.67.222.222',
    ];

    /**
     * @param  list<string>  $publicNameservers
     */
    public function __construct(
        private readonly Resolver $publicResolver,
        private readonly AuthoritativeResolver $authoritative,
        private readonly array $publicNameservers = self::DEFAULT_NAMESERVERS,
    ) {}

    public function check(string $host, RecordType $type, string $zone): PropagationReport
    {
        $authoritativeValues = $this->normalize($this->authoritativeValues($host, $type, $zone));

        $results = [];
        $allAgree = true;

        foreach ($this->publicNameservers as $nameserver) {
            $values = $this->normalize($this->publicValues($host, $type, $nameserver));
            $agrees = $authoritativeValues !== [] && $values === $authoritativeValues;
            $allAgree = $allAgree && $agrees;

            $results[] = new ResolverResult($nameserver, $values, $agrees);
        }

        return new PropagationReport($authoritativeValues, $results, $this->status($authoritativeValues, $allAgree));
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
    private function publicValues(string $host, RecordType $type, string $nameserver): array
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
