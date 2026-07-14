<?php

declare(strict_types=1);

namespace Cbox\Dns\Diagnostics\Checks;

use Cbox\Dns\Diagnostics\Contracts\Check;
use Cbox\Dns\Diagnostics\DiagnosticContext;
use Cbox\Dns\Diagnostics\Finding;
use Cbox\Dns\Diagnostics\Support\IpAddress;
use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Exceptions\DnsException;

/**
 * Validates the domain's mail routing (RFC 5321 §5). It checks that MX exists, that
 * each exchange is a resolvable public hostname (never an IP literal — RFC 1035 §3.3.9
 * — and never a CNAME — RFC 2181 §10.3), that there is more than one for redundancy,
 * and that each mail-server IP has a PTR that forward-confirms (FCrDNS), which many
 * receivers require.
 *
 * A `.` "null MX" (RFC 7505) is honoured as an explicit "this domain sends/receives
 * no mail" and reported as Info, not an error.
 */
final class MxCheck implements Check
{
    private const string CATEGORY = 'Email';

    public function run(DiagnosticContext $ctx): array
    {
        try {
            $response = $ctx->resolver->query($ctx->domain, RecordType::MX);
        } catch (DnsException) {
            return [Finding::warning(self::CATEGORY, 'mx.presence', 'MX lookup failed — mail routing cannot be evaluated.')];
        }

        $exchanges = array_values(array_filter(
            $response->values(),
            static fn (string $exchange): bool => $exchange !== '',
        ));

        if ($exchanges === []) {
            return [Finding::warning(
                self::CATEGORY,
                'mx.presence',
                'No MX record — the domain cannot receive mail at its own servers.',
            )];
        }

        if ($exchanges === ['.']) {
            return [Finding::info(
                self::CATEGORY,
                'mx.presence',
                'Null MX (.) is published — the domain explicitly accepts no mail (RFC 7505).',
            )];
        }

        $findings = [];

        $findings[] = count($exchanges) >= 2
            ? Finding::info(self::CATEGORY, 'mx.redundancy', count($exchanges).' MX hosts are published.', ['mx' => $exchanges])
            : Finding::warning(self::CATEGORY, 'mx.redundancy', 'Only one MX host — no mail-delivery redundancy.', ['mx' => $exchanges]);

        foreach ($exchanges as $exchange) {
            foreach ($this->inspectExchange($ctx, $exchange) as $finding) {
                $findings[] = $finding;
            }
        }

        return $findings;
    }

    /**
     * @return list<Finding>
     */
    private function inspectExchange(DiagnosticContext $ctx, string $exchange): array
    {
        $host = rtrim($exchange, '.');

        if (IpAddress::isIp($host)) {
            return [Finding::error(
                self::CATEGORY,
                'mx.target',
                "MX target {$host} is an IP literal — an MX must name a hostname (RFC 1035 §3.3.9).",
                ['mx' => $host],
            )];
        }

        if ($this->isCname($ctx, $host)) {
            return [Finding::error(
                self::CATEGORY,
                'mx.target',
                "MX target {$host} is a CNAME — an MX must point at an address record, not an alias (RFC 2181 §10.3).",
                ['mx' => $host],
            )];
        }

        $addresses = $ctx->addresses($host);

        if ($addresses === []) {
            return [Finding::error(
                self::CATEGORY,
                'mx.target',
                "MX target {$host} does not resolve to any address — mail to it will bounce.",
                ['mx' => $host],
            )];
        }

        $public = array_values(array_filter($addresses, IpAddress::isPublic(...)));

        if ($public === []) {
            return [Finding::error(
                self::CATEGORY,
                'mx.target',
                "MX target {$host} resolves only to private/reserved addresses, unreachable from the internet.",
                ['mx' => $host, 'addresses' => $addresses],
            )];
        }

        return $this->inspectReverseDns($ctx, $host, $public);
    }

    /**
     * @param  list<string>  $addresses
     * @return list<Finding>
     */
    private function inspectReverseDns(DiagnosticContext $ctx, string $host, array $addresses): array
    {
        $findings = [];

        foreach ($addresses as $ip) {
            $pointer = IpAddress::reversePointer($ip);

            if ($pointer === null) {
                continue;
            }

            $names = $this->ptrNames($ctx, $pointer);

            if ($names === []) {
                $findings[] = Finding::warning(
                    self::CATEGORY,
                    'mx.ptr',
                    "MX {$host} address {$ip} has no PTR record — receivers may reject its mail.",
                    ['mx' => $host, 'ip' => $ip],
                );

                continue;
            }

            if (! $this->forwardConfirms($ctx, $names, $ip)) {
                $findings[] = Finding::warning(
                    self::CATEGORY,
                    'mx.fcrdns',
                    "MX {$host} address {$ip} is not forward-confirmed (FCrDNS): its PTR name does not resolve back to {$ip}.",
                    ['mx' => $host, 'ip' => $ip, 'ptr' => $names],
                );

                continue;
            }

            $findings[] = Finding::info(
                self::CATEGORY,
                'mx.fcrdns',
                "MX {$host} address {$ip} has forward-confirmed reverse DNS.",
                ['mx' => $host, 'ip' => $ip, 'ptr' => $names],
            );
        }

        return $findings;
    }

    private function isCname(DiagnosticContext $ctx, string $host): bool
    {
        try {
            return $ctx->resolver->query($host, RecordType::CNAME)->records !== [];
        } catch (DnsException) {
            return false;
        }
    }

    /**
     * @return list<string>
     */
    private function ptrNames(DiagnosticContext $ctx, string $pointer): array
    {
        try {
            return array_map(
                static fn (string $name): string => rtrim($name, '.'),
                $ctx->resolver->query($pointer, RecordType::PTR)->values(),
            );
        } catch (DnsException) {
            return [];
        }
    }

    /**
     * @param  list<string>  $names
     */
    private function forwardConfirms(DiagnosticContext $ctx, array $names, string $ip): bool
    {
        foreach ($names as $name) {
            if (in_array($ip, $ctx->addresses($name), true)) {
                return true;
            }
        }

        return false;
    }
}
