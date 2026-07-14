<?php

declare(strict_types=1);

namespace Cbox\Dns\Diagnostics\Checks;

use Cbox\Dns\Diagnostics\Contracts\Check;
use Cbox\Dns\Diagnostics\DiagnosticContext;
use Cbox\Dns\Diagnostics\Finding;
use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Exceptions\DnsException;
use Cbox\Dns\Support\IpAddress;

/**
 * Checks the zone's nameservers themselves: there should be at least two (RFC 1034
 * §4.1); none may be a CNAME (RFC 2181 §10.3); each must resolve to a public IP
 * (never RFC1918); each must actually respond and answer AUTHORITATIVELY for the
 * zone (a server that answers non-authoritatively is "lame"); and none should
 * offer open recursion for a foreign name.
 *
 * Lame vs unresponsive is distinguished by the SOA probe: an empty answer means the
 * server did not respond, while a non-authoritative answer means it responded but
 * is not authoritative for the zone.
 */
class NameserverCheck implements Check
{
    private const string CATEGORY = 'Nameservers';

    /** A name outside the tested zone, used to detect open recursion. */
    private const string RECURSION_PROBE = 'recursion-probe.cbox-diagnostics.example';

    public function run(DiagnosticContext $ctx): array
    {
        $nameservers = $ctx->nameservers();

        $findings = [count($nameservers) >= 2
            ? Finding::info(self::CATEGORY, 'ns.count', count($nameservers).' nameservers are delegated.', ['nameservers' => $nameservers])
            : Finding::warning(self::CATEGORY, 'ns.count', 'Fewer than two nameservers are delegated — a single point of failure.', ['nameservers' => $nameservers])];

        foreach ($nameservers as $nameserver) {
            foreach ($this->inspect($ctx, $nameserver) as $finding) {
                $findings[] = $finding;
            }
        }

        return $findings;
    }

    /**
     * @return list<Finding>
     */
    private function inspect(DiagnosticContext $ctx, string $nameserver): array
    {
        if ($this->isCname($ctx, $nameserver)) {
            return [Finding::error(
                self::CATEGORY,
                'ns.cname',
                "Nameserver {$nameserver} is a CNAME — an NS must name a host with address records (RFC 2181 §10.3).",
                ['nameserver' => $nameserver],
            )];
        }

        $addresses = $ctx->addresses($nameserver);

        if ($addresses === []) {
            return [Finding::warning(
                self::CATEGORY,
                'ns.resolve',
                "Nameserver {$nameserver} does not resolve to any address.",
                ['nameserver' => $nameserver],
            )];
        }

        $findings = [];

        foreach ($addresses as $address) {
            foreach ($this->inspectAddress($ctx, $nameserver, $address) as $finding) {
                $findings[] = $finding;
            }
        }

        return $findings;
    }

    /**
     * @return list<Finding>
     */
    private function inspectAddress(DiagnosticContext $ctx, string $nameserver, string $address): array
    {
        if (! IpAddress::isPublic($address)) {
            return [Finding::error(
                self::CATEGORY,
                'ns.private-ip',
                "Nameserver {$nameserver} resolves to a private/reserved address {$address}, unreachable from the internet.",
                ['nameserver' => $nameserver, 'address' => $address],
            )];
        }

        $findings = [];

        $findings[] = $this->probeAuthority($ctx, $nameserver, $address);

        if ($this->offersRecursion($ctx, $address)) {
            $findings[] = Finding::warning(
                self::CATEGORY,
                'ns.recursion',
                "Nameserver {$nameserver} ({$address}) answers recursive queries for foreign names — it is an open resolver.",
                ['nameserver' => $nameserver, 'address' => $address],
            );
        }

        return $findings;
    }

    private function probeAuthority(DiagnosticContext $ctx, string $nameserver, string $address): Finding
    {
        try {
            $response = $ctx->resolver->query($ctx->domain, RecordType::SOA, $address, recursion: false);
        } catch (DnsException) {
            return Finding::warning(
                self::CATEGORY,
                'ns.respond',
                "Nameserver {$nameserver} ({$address}) did not respond to a SOA query.",
                ['nameserver' => $nameserver, 'address' => $address],
            );
        }

        if ($response->records === []) {
            return Finding::warning(
                self::CATEGORY,
                'ns.respond',
                "Nameserver {$nameserver} ({$address}) returned no SOA — it did not answer for the zone.",
                ['nameserver' => $nameserver, 'address' => $address],
            );
        }

        if (! $response->authoritative) {
            return Finding::error(
                self::CATEGORY,
                'ns.lame',
                "Nameserver {$nameserver} ({$address}) is lame — it answers but not authoritatively for the zone.",
                ['nameserver' => $nameserver, 'address' => $address],
            );
        }

        return Finding::info(
            self::CATEGORY,
            'ns.authoritative',
            "Nameserver {$nameserver} ({$address}) answers authoritatively for the zone.",
            ['nameserver' => $nameserver, 'address' => $address],
        );
    }

    private function isCname(DiagnosticContext $ctx, string $host): bool
    {
        try {
            return $ctx->resolver->query($host, RecordType::CNAME)->records !== [];
        } catch (DnsException) {
            return false;
        }
    }

    private function offersRecursion(DiagnosticContext $ctx, string $address): bool
    {
        try {
            return $ctx->resolver->query(self::RECURSION_PROBE, RecordType::A, $address, recursion: true)->records !== [];
        } catch (DnsException) {
            return false;
        }
    }
}
