<?php

declare(strict_types=1);

namespace Cbox\Dns\Resolvers;

use Cbox\Dns\Contracts\Resolver;
use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Exceptions\ResolutionFailed;
use Cbox\Dns\Testing\FakeResolver;
use Cbox\Dns\ValueObjects\DnsResponse;

/**
 * Reads a record straight from a zone's authoritative nameservers, bypassing every
 * recursive resolver's cache. This is the reliable path for ownership verification
 * and propagation checks: it discovers the zone's NS set, resolves those hostnames
 * to IPs, then queries the target record directly against an authoritative server
 * with recursion disabled.
 *
 * All resolution flows through the composed {@see Resolver}, so a
 * {@see FakeResolver} fully drives it with no network.
 */
final class AuthoritativeResolver
{
    public function __construct(
        private readonly Resolver $resolver = new SocketResolver,
    ) {}

    /**
     * The authoritative nameserver IPs for a zone: resolve the zone's NS records
     * (recursively), then resolve each NS hostname to its A/AAAA addresses.
     *
     * @return list<string>
     */
    public function authoritativeFor(string $zone): array
    {
        $zone = rtrim($zone, '.');
        $nameservers = $this->resolver->query($zone, RecordType::NS)->values();

        $ips = [];

        foreach ($nameservers as $nameserver) {
            $nameserver = rtrim($nameserver, '.');

            foreach ([RecordType::A, RecordType::AAAA] as $ipType) {
                foreach ($this->resolver->query($nameserver, $ipType)->values() as $ip) {
                    $ips[$ip] = true;
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
