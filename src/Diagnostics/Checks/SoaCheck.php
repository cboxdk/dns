<?php

declare(strict_types=1);

namespace Cbox\Dns\Diagnostics\Checks;

use Cbox\Dns\Diagnostics\Contracts\Check;
use Cbox\Dns\Diagnostics\DiagnosticContext;
use Cbox\Dns\Diagnostics\Finding;
use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Exceptions\DnsException;
use Cbox\Dns\ValueObjects\Soa;

/**
 * Validates the zone's SOA (RFC 1035 §3.3.13, RFC 1912 §2.2). It reads the SOA
 * directly from each authoritative nameserver, so it can both parse the record and
 * confirm every server serves the SAME serial (a divergence means a zone transfer
 * has not completed). It also checks that MNAME is one of the zone's listed
 * nameservers and that the refresh/retry/expire/minimum timers are internally sane.
 */
class SoaCheck implements Check
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

        $primary = Soa::fromPresentation((string) array_values($soaByAddress)[0]);

        if ($primary === null) {
            return [Finding::error(
                self::CATEGORY,
                'soa.parse',
                'The SOA record could not be parsed into its seven fields.',
                ['soa' => array_values($soaByAddress)[0]],
            )];
        }

        return [
            $this->checkMname($primary->mname, $nameservers),
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
     * @return list<Finding>
     */
    private function checkTimers(Soa $soa): array
    {
        $context = [
            'mname' => $soa->mname,
            'serial' => $soa->serial,
            'refresh' => $soa->refresh,
            'retry' => $soa->retry,
            'expire' => $soa->expire,
            'minimum' => $soa->minimum,
        ];

        $findings = [];

        if ($soa->retry >= $soa->refresh) {
            $findings[] = Finding::warning(
                self::CATEGORY,
                'soa.timers',
                "SOA retry ({$soa->retry}s) should be less than refresh ({$soa->refresh}s).",
                $context,
            );
        }

        if ($soa->expire < $soa->refresh) {
            $findings[] = Finding::warning(
                self::CATEGORY,
                'soa.timers',
                "SOA expire ({$soa->expire}s) should be at least the refresh interval ({$soa->refresh}s).",
                $context,
            );
        }

        if ($soa->minimum < self::MINIMUM_FLOOR || $soa->minimum > self::MINIMUM_CEILING) {
            $findings[] = Finding::warning(
                self::CATEGORY,
                'soa.timers',
                "SOA minimum ({$soa->minimum}s) is outside the sane ".self::MINIMUM_FLOOR.'–'.self::MINIMUM_CEILING.'s range.',
                $context,
            );
        }

        if ($findings === []) {
            $findings[] = Finding::info(self::CATEGORY, 'soa.timers', 'SOA timers (refresh/retry/expire/minimum) are internally consistent.', $context);
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
            $serials[$address] = Soa::fromPresentation($value)?->serial;
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
}
