<?php

declare(strict_types=1);

namespace Cbox\Dns\Tracing;

use Cbox\Dns\Contracts\Resolver;
use Cbox\Dns\Enums\Rcode;
use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Exceptions\DnsException;
use Cbox\Dns\Resolvers\SocketResolver;
use Cbox\Dns\Support\Hostname;
use Cbox\Dns\Support\IpAddress;
use Cbox\Dns\ValueObjects\DnsRecord;
use Cbox\Dns\ValueObjects\DnsResponse;

/**
 * Traces a name's delegation from the root down, like `dig +trace`: at each zone
 * cut it asks an authoritative server (recursion off), follows the referral to the
 * child zone, and records the hop — so you can see exactly which nameservers
 * delegate which zone, and where a broken delegation stops.
 *
 * Robust by construction. Every downward step must make progress — the referred
 * child zone must be a strictly-longer, in-bailiwick descendant of the current zone
 * — and already-visited zones are refused, so a self-referential or looping
 * delegation terminates instead of spinning. A per-server query failure is caught
 * and the next server tried; a total dead end ends the trace with a reason rather
 * than an exception. The whole walk is bounded by {@see self::MAX_HOPS}.
 *
 * All queries flow through the injected {@see Resolver}, so a fake drives a trace
 * offline.
 */
class DelegationTracer
{
    /** Hard cap on delegation depth — far beyond any real zone hierarchy. */
    public const int MAX_HOPS = 32;

    /** Cap on referral nameservers whose glue-less address we will resolve per hop. */
    private const int MAX_NS_RESOLVED = 4;

    public function __construct(
        private readonly Resolver $resolver = new SocketResolver,
    ) {}

    /**
     * Trace the delegation of `$name` for `$type` (NS by default) from the root.
     */
    public function trace(string $name, RecordType $type = RecordType::NS): DelegationTrace
    {
        $name = strtolower(Hostname::toAscii($name));

        $hops = [];
        $visited = [];
        $servers = RootHints::ipv4();
        $zone = '.';
        $answer = [];
        $completed = false;
        $reason = null;

        for ($hop = 0; $hop < self::MAX_HOPS; $hop++) {
            [$serverName, $serverIp, $response] = $this->askAny($servers, $name, $type);

            if ($response === null) {
                $hops[] = new DelegationHop($zone, $serverName, $serverIp, false, false, Rcode::ServFail);
                $reason = "no nameserver for zone {$zone} answered";
                break;
            }

            // A direct answer for the queried type ends the trace.
            if ($response->records !== []) {
                $hops[] = new DelegationHop($zone, $serverName, $serverIp, true, $response->authoritative, $response->rcode);
                $answer = $response->records;
                $completed = true;
                break;
            }

            $referral = $response->authorityOfType(RecordType::NS);

            if ($referral === []) {
                // Authoritative NODATA/NXDOMAIN, or an apex answer with no delegation.
                $hops[] = new DelegationHop($zone, $serverName, $serverIp, true, $response->authoritative, $response->rcode);
                $completed = $response->authoritative;
                $reason = $response->authoritative ? null : 'server returned neither an answer nor a referral';
                break;
            }

            $childZone = strtolower(rtrim($referral[0]->name, '.'));
            $childZone = $childZone === '' ? '.' : $childZone;

            if (! $this->makesProgress($childZone, $zone, $name) || in_array($childZone, $visited, true)) {
                $hops[] = new DelegationHop($zone, $serverName, $serverIp, true, $response->authoritative, $response->rcode, $childZone);
                $reason = "delegation to {$childZone} does not descend towards {$name} (loop or lame delegation)";
                break;
            }

            // Only NS records owned by the child zone are its delegation — ignore any
            // foreign RRsets a hostile parent might splice into the authority section.
            $childNs = array_values(array_filter(
                $referral,
                static fn (DnsRecord $r): bool => strtolower(rtrim($r->name, '.')) === $childZone,
            ));
            $nsNames = $this->names($childNs);
            $glue = $this->glue($nsNames, $response);
            // A name => IP map for the next hop: glue where present, else resolved
            // per nameserver (so the name↔IP correspondence stays correct).
            $servers = $glue !== [] ? $glue : $this->resolveNsAddresses($nsNames);

            $hops[] = new DelegationHop($zone, $serverName, $serverIp, true, $response->authoritative, $response->rcode, $childZone, $nsNames, $glue);

            if ($servers === []) {
                $reason = "no reachable address for the nameservers of {$childZone}";
                break;
            }

            $visited[] = $zone;
            $zone = $childZone;
        }

        if ($hop >= self::MAX_HOPS) {
            $reason = 'delegation depth exceeded '.self::MAX_HOPS.' hops';
        }

        return new DelegationTrace($name, $type, $hops, $answer, $completed, $reason);
    }

    /**
     * Trace the reverse (PTR) delegation of an IP address — the in-addr.arpa /
     * ip6.arpa chain, which is where CIDR / reverse-zone delegation lives.
     */
    public function traceReverse(string $ip): DelegationTrace
    {
        $pointer = IpAddress::reversePointer($ip);

        if ($pointer === null) {
            return new DelegationTrace($ip, RecordType::PTR, [], [], false, "not an IP address: {$ip}");
        }

        return $this->trace($pointer, RecordType::PTR);
    }

    /**
     * Ask each server in turn until one answers, returning [name, ip, response].
     *
     * @param  array<string, string>  $servers  nameserver name => IP
     * @return array{0: string, 1: string, 2: DnsResponse|null}
     */
    private function askAny(array $servers, string $name, RecordType $type): array
    {
        $lastName = '';
        $lastIp = '';

        foreach ($servers as $serverName => $ip) {
            $lastName = $serverName;
            $lastIp = $ip;

            try {
                return [$lastName, $ip, $this->resolver->query($name, $type, $ip, recursion: false)];
            } catch (DnsException) {
                // try the next server
            }
        }

        return [$lastName, $lastIp, null];
    }

    /**
     * A referred child zone is a valid downward step only if it is a strictly-longer
     * descendant of the current zone AND in-bailiwick for the queried name (the name
     * equals it or sits beneath it) — this is what guarantees the trace terminates.
     */
    private function makesProgress(string $childZone, string $currentZone, string $name): bool
    {
        if ($this->labelCount($childZone) <= $this->labelCount($currentZone)) {
            return false;
        }

        if ($childZone === '.') {
            return false;
        }

        return $name === $childZone || str_ends_with($name, '.'.$childZone);
    }

    /**
     * @param  list<string>  $nsNames
     * @return array<string, string> nameserver name => glue IP (public only)
     */
    private function glue(array $nsNames, DnsResponse $response): array
    {
        $glue = [];

        foreach ($response->additional as $record) {
            if ($record->type !== RecordType::A && $record->type !== RecordType::AAAA) {
                continue;
            }

            $owner = strtolower(rtrim($record->name, '.'));

            if (in_array($owner, array_map(strtolower(...), $nsNames), true) && IpAddress::isPublic($record->value)) {
                $glue[$owner] = $record->value;
            }
        }

        return $glue;
    }

    /**
     * Resolve the referral nameservers that shipped no glue, via the (recursive)
     * resolver — capped, public addresses only, keeping the name↔IP correspondence.
     * Both A and AAAA are tried, so an IPv6-only nameserver is still reachable.
     *
     * @param  list<string>  $nsNames
     * @return array<string, string> nameserver name => IP
     */
    private function resolveNsAddresses(array $nsNames): array
    {
        $map = [];

        foreach (array_slice($nsNames, 0, self::MAX_NS_RESOLVED) as $ns) {
            foreach ([RecordType::A, RecordType::AAAA] as $type) {
                try {
                    foreach ($this->resolver->query($ns, $type)->values() as $ip) {
                        if (IpAddress::isPublic($ip) && ! isset($map[$ns])) {
                            $map[$ns] = $ip; // one address per nameserver is enough to query it
                        }
                    }
                } catch (DnsException) {
                    // skip an unresolvable nameserver / family
                }
            }
        }

        return $map;
    }

    /**
     * @param  list<DnsRecord>  $records
     * @return list<string>
     */
    private function names(array $records): array
    {
        return array_values(array_unique(array_map(
            static fn (DnsRecord $r): string => strtolower(rtrim($r->value, '.')),
            $records,
        )));
    }

    private function labelCount(string $zone): int
    {
        $zone = rtrim($zone, '.');

        return $zone === '' ? 0 : count(explode('.', $zone));
    }
}
