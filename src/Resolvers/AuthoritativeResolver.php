<?php

declare(strict_types=1);

namespace Cbox\Dns\Resolvers;

use Cbox\Dns\Contracts\Resolver;
use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Exceptions\ResolutionFailed;
use Cbox\Dns\Support\IpAddress;
use Cbox\Dns\Testing\FakeResolver;
use Cbox\Dns\ValueObjects\DnsResponse;

/**
 * Reads a record straight from a zone's authoritative nameservers, bypassing every
 * recursive resolver's cache. This is the reliable path for ownership verification
 * and propagation checks: it discovers the zone's NS set, resolves those hostnames
 * to IPs, then queries the target record directly against an authoritative server
 * with recursion disabled.
 *
 * SSRF hardening: the NS set is attacker-influenced (a domain owner controls their
 * own NS records and glue), so by default only globally-routable public addresses
 * are queried — a zone pointing its NS at `127.0.0.1`, `169.254.169.254`, or an
 * RFC1918 host cannot make this resolver probe internal infrastructure. The NS
 * fan-out is also capped so a zone cannot amplify a single check into thousands of
 * outbound queries. `allowNonPublicNameservers: true` lifts the address filter for
 * legitimate LAN/test use.
 *
 * All resolution flows through the composed {@see Resolver}, so a
 * {@see FakeResolver} fully drives it with no network.
 */
class AuthoritativeResolver
{
    /** Cap on NS names resolved per zone — a malicious zone cannot fan out without bound. */
    public const int MAX_NAMESERVERS = 20;

    /** Cap on addresses used per NS name. */
    public const int MAX_ADDRESSES_PER_NAMESERVER = 8;

    public function __construct(
        private readonly Resolver $resolver = new SocketResolver,
        private readonly bool $allowNonPublicNameservers = false,
    ) {}

    /**
     * The authoritative nameserver IPs for a zone: resolve the zone's NS records
     * (recursively), then resolve each NS hostname to its A/AAAA addresses. Only
     * public addresses are returned unless non-public servers are explicitly
     * allowed, and the NS fan-out is capped.
     *
     * @return list<string>
     */
    public function authoritativeFor(string $zone): array
    {
        $zone = rtrim($zone, '.');
        $nameservers = array_slice($this->resolver->query($zone, RecordType::NS)->values(), 0, self::MAX_NAMESERVERS);

        $ips = [];

        foreach ($nameservers as $nameserver) {
            $nameserver = rtrim($nameserver, '.');
            $found = 0;

            foreach ([RecordType::A, RecordType::AAAA] as $ipType) {
                foreach ($this->resolver->query($nameserver, $ipType)->values() as $ip) {
                    if (! $this->allowNonPublicNameservers && ! IpAddress::isPublic($ip)) {
                        continue; // deny-by-default: never probe internal/reserved space
                    }

                    if ($found >= self::MAX_ADDRESSES_PER_NAMESERVER) {
                        break 2;
                    }

                    $ips[$ip] = true;
                    $found++;
                }
            }
        }

        return array_keys($ips);
    }

    /**
     * Query `$host` of `$type` directly against `$zone`'s authoritative servers
     * with recursion disabled, returning the first server that answers. Every
     * NS IP is tried; {@see ResolutionFailed} is surfaced only when none answer
     * (or the zone exposes no reachable authoritative server).
     */
    public function query(string $host, RecordType $type, string $zone, bool $dnssec = false): DnsResponse
    {
        $nameservers = $this->authoritativeFor($zone);

        if ($nameservers === []) {
            throw ResolutionFailed::make($zone, 'no authoritative nameservers found');
        }

        $lastFailure = ResolutionFailed::make($zone, 'no authoritative nameserver answered');

        foreach ($nameservers as $nameserver) {
            try {
                return $this->resolver->query($host, $type, $nameserver, recursion: false, dnssec: $dnssec);
            } catch (ResolutionFailed $failure) {
                $lastFailure = $failure;
            }
        }

        throw $lastFailure;
    }
}
