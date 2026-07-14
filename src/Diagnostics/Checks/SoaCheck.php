<?php

declare(strict_types=1);

namespace Cbox\Dns\Diagnostics\Checks;

use Cbox\Dns\Diagnostics\Contracts\Check;
use Cbox\Dns\Diagnostics\DiagnosticContext;
use Cbox\Dns\Diagnostics\Finding;
use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Exceptions\DnsException;

/**
 * Validates the zone's SOA (RFC 1035 §3.3.13, RFC 1912 §2.2). It reads the SOA
 * directly from each authoritative nameserver, so it can both parse the record and
 * confirm every server serves the SAME serial (a divergence means a zone transfer
 * has not completed). It also checks that MNAME is one of the zone's listed
 * nameservers and that the refresh/retry/expire/minimum timers are internally sane.
 *
 * @phpstan-type SoaTimers array{mname: string, serial: int, refresh: int, retry: int, expire: int, minimum: int}
 */
final class SoaCheck implements Check
{
    private const string CATEGORY = 'SOA';

    private const int MINIMUM_FLOOR = 300;

    private const int MINIMUM_CEILING = 86400;

    public function run(DiagnosticContext $ctx): array
    {
        $nameservers = $ctx->nameservers();
        $addresses = $this->nameserverAddresses($ctx, $nameservers);

        /** @var array<string, string> $soaByAddress raw SOA value keyed by NS address */
        $soaByAddress = [];

        foreach ($addresses as $address) {
            $value = $this->soaAt($ctx, $address);

            if ($value !== null) {
                $soaByAddress[$address] = $value;
            }
        }

        if ($soaByAddress === []) {
            return [Finding::error(
                self::CATEGORY,
                'soa.presence',
                'No authoritative nameserver returned a SOA record for the zone.',
            )];
        }

        $primary = $this->parse((string) array_values($soaByAddress)[0]);

        if ($primary === null) {
            return [Finding::error(
                self::CATEGORY,
                'soa.parse',
                'The SOA record could not be parsed into its seven fields.',
                ['soa' => array_values($soaByAddress)[0]],
            )];
        }

        return [
            $this->checkMname($primary['mname'], $nameservers),
            ...$this->checkTimers($primary),
            $this->checkSerialAgreement($soaByAddress),
        ];
    }

    /**
     * @param  list<string>  $nameservers
     * @return list<string>
     */
    private function nameserverAddresses(DiagnosticContext $ctx, array $nameservers): array
    {
        $addresses = [];

        foreach ($nameservers as $nameserver) {
            foreach ($ctx->addresses($nameserver) as $address) {
                $addresses[$address] = true;
            }
        }

        return array_keys($addresses);
    }

    private function soaAt(DiagnosticContext $ctx, string $address): ?string
    {
        try {
            $values = $ctx->resolver->query($ctx->domain, RecordType::SOA, $address, recursion: false)->values();
        } catch (DnsException) {
            return null;
        }

        return $values[0] ?? null;
    }

    /**
     * @param  list<string>  $nameservers
     */
    private function checkMname(string $mname, array $nameservers): Finding
    {
        $normalised = array_map(static fn (string $ns): string => strtolower(rtrim($ns, '.')), $nameservers);

        if (in_array(strtolower(rtrim($mname, '.')), $normalised, true)) {
            return Finding::info(self::CATEGORY, 'soa.mname', "SOA MNAME {$mname} is one of the zone's nameservers.", ['mname' => $mname]);
        }

        return Finding::warning(
            self::CATEGORY,
            'soa.mname',
            "SOA MNAME {$mname} is not listed among the zone's NS records.",
            ['mname' => $mname, 'nameservers' => $nameservers],
        );
    }

    /**
     * @param  array{mname: string, serial: int, refresh: int, retry: int, expire: int, minimum: int}  $soa
     * @return list<Finding>
     */
    private function checkTimers(array $soa): array
    {
        $findings = [];

        if ($soa['retry'] >= $soa['refresh']) {
            $findings[] = Finding::warning(
                self::CATEGORY,
                'soa.timers',
                "SOA retry ({$soa['retry']}s) should be less than refresh ({$soa['refresh']}s).",
                $soa,
            );
        }

        if ($soa['expire'] < $soa['refresh']) {
            $findings[] = Finding::warning(
                self::CATEGORY,
                'soa.timers',
                "SOA expire ({$soa['expire']}s) should be at least the refresh interval ({$soa['refresh']}s).",
                $soa,
            );
        }

        if ($soa['minimum'] < self::MINIMUM_FLOOR || $soa['minimum'] > self::MINIMUM_CEILING) {
            $findings[] = Finding::warning(
                self::CATEGORY,
                'soa.timers',
                "SOA minimum ({$soa['minimum']}s) is outside the sane ".self::MINIMUM_FLOOR.'–'.self::MINIMUM_CEILING.'s range.',
                $soa,
            );
        }

        if ($findings === []) {
            $findings[] = Finding::info(self::CATEGORY, 'soa.timers', 'SOA timers (refresh/retry/expire/minimum) are internally consistent.', $soa);
        }

        return $findings;
    }

    /**
     * @param  array<string, string>  $soaByAddress
     */
    private function checkSerialAgreement(array $soaByAddress): Finding
    {
        $serials = [];

        foreach ($soaByAddress as $address => $value) {
            $parsed = $this->parse($value);
            $serials[$address] = $parsed['serial'] ?? null;
        }

        if (count(array_unique($serials, SORT_REGULAR)) > 1) {
            return Finding::warning(
                self::CATEGORY,
                'soa.serial',
                'Authoritative nameservers disagree on the SOA serial — a zone transfer has not fully propagated.',
                ['serials' => $serials],
            );
        }

        return Finding::info(
            self::CATEGORY,
            'soa.serial',
            'All authoritative nameservers agree on the SOA serial.',
            ['serials' => $serials],
        );
    }

    /**
     * @return array{mname: string, serial: int, refresh: int, retry: int, expire: int, minimum: int}|null
     */
    private function parse(string $value): ?array
    {
        $parts = preg_split('/\s+/', trim($value)) ?: [];

        if (count($parts) < 7) {
            return null;
        }

        foreach ([2, 3, 4, 5, 6] as $index) {
            if (! ctype_digit($parts[$index])) {
                return null;
            }
        }

        return [
            'mname' => $parts[0],
            'serial' => (int) $parts[2],
            'refresh' => (int) $parts[3],
            'retry' => (int) $parts[4],
            'expire' => (int) $parts[5],
            'minimum' => (int) $parts[6],
        ];
    }
}
