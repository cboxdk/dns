<?php

declare(strict_types=1);

namespace Cbox\Dns\Spf;

use Cbox\Dns\Contracts\Resolver;
use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Exceptions\DnsException;
use Cbox\Dns\Resolvers\SocketResolver;
use Cbox\Dns\Support\Hostname;
use Cbox\Dns\ValueObjects\SpfPolicy;

/**
 * Expands a domain's SPF policy (RFC 7208) into the complete set of authorized
 * sending endpoints, recursively following `include:` and `redirect=` and expanding
 * `a` / `mx` mechanisms into their addresses.
 *
 * Robust and terminating by construction: the RFC 7208 §4.6.4 budget of 10
 * DNS-querying mechanisms is enforced across the WHOLE tree (not per include), and a
 * domain is never evaluated twice, so an `include:` loop or a runaway policy stops
 * with `exceededLookupLimit` / an error rather than spinning.
 *
 * All lookups flow through the injected {@see Resolver}, so a fake drives an
 * expansion offline.
 */
class SpfResolver
{
    public function __construct(
        private readonly Resolver $resolver = new SocketResolver,
    ) {}

    /**
     * Expand the SPF policy of `$domain`.
     */
    public function resolve(string $domain): SpfEvaluation
    {
        return $this->evaluate(strtolower(Hostname::toAscii($domain)), new SpfLimits);
    }

    /**
     * @param  list<string>  $path  the include/redirect ancestors of this domain —
     *                              used for loop detection. Passed by value so that
     *                              two branches including the same domain (a diamond)
     *                              are NOT mistaken for a loop; only a true cycle (a
     *                              domain that includes one of its own ancestors) is.
     */
    private function evaluate(string $domain, SpfLimits $limits, array $path = []): SpfEvaluation
    {
        if (in_array($domain, $path, true)) {
            return $this->error($domain, null, $limits, "include loop at {$domain}");
        }

        $path[] = $domain;

        $record = $this->fetchSpf($domain, $limits);

        if ($record === null) {
            return $this->error($domain, null, $limits, "no SPF record for {$domain}");
        }

        $policy = SpfPolicy::parse($record);

        if ($policy === null) {
            return $this->error($domain, $record, $limits, "malformed SPF record for {$domain}");
        }

        $ip4 = [];
        $ip6 = [];
        $includes = [];
        $errors = [];

        foreach ($policy->mechanisms as $mechanism) {
            if ($limits->exceeded()) {
                $errors[] = 'exceeded the RFC 7208 lookup limit';
                break;
            }

            match ($mechanism->name) {
                'ip4' => $ip4[] = $mechanism->value ?? '',
                'ip6' => $ip6[] = $mechanism->value ?? '',
                'a' => $this->expandAddresses($mechanism->value ?? $domain, $limits, $ip4, $ip6, $errors),
                'mx' => $this->expandMx($mechanism->value ?? $domain, $limits, $ip4, $ip6, $errors),
                'include' => $this->expandInclude($mechanism->value, $limits, $path, $includes, $errors),
                'ptr', 'exists' => $limits->charge(), // counted per RFC; not expanded to endpoints
                default => null, // 'all' and bare mechanisms carry no endpoints
            };

            if ($mechanism->name === 'all') {
                break; // 'all' matches everything after it — later terms are unreachable
            }
        }

        $redirect = null;
        if ($policy->allQualifier === null && $policy->redirect !== null && ! $limits->exceeded()) {
            $redirect = $limits->charge()
                ? $this->evaluate(strtolower(rtrim($policy->redirect, '.')), $limits, $path)
                : null;

            if ($redirect === null) {
                $errors[] = 'exceeded the RFC 7208 lookup limit before redirect';
            }
        }

        return new SpfEvaluation(
            $domain,
            $record,
            array_values(array_filter($ip4, static fn (string $v): bool => $v !== '')),
            array_values(array_filter($ip6, static fn (string $v): bool => $v !== '')),
            $includes,
            $redirect,
            $policy->allQualifier,
            $limits->lookups,
            $limits->exceeded(),
            $errors,
        );
    }

    /**
     * @param  list<string>  $ip4
     * @param  list<string>  $ip6
     * @param  list<string>  $errors
     */
    private function expandAddresses(string $host, SpfLimits $limits, array &$ip4, array &$ip6, array &$errors): void
    {
        if (! $limits->charge()) {
            $errors[] = 'exceeded the RFC 7208 lookup limit at a: '.$host;

            return;
        }

        $host = strtolower(rtrim($host, '.'));
        $a = $this->values($host, RecordType::A);
        $aaaa = $this->values($host, RecordType::AAAA);

        foreach ($a as $ip) {
            $ip4[] = $ip;
        }

        foreach ($aaaa as $ip) {
            $ip6[] = $ip;
        }

        if ($a === [] && $aaaa === []) {
            $limits->voidLookups++;
        }
    }

    /**
     * @param  list<string>  $ip4
     * @param  list<string>  $ip6
     * @param  list<string>  $errors
     */
    private function expandMx(string $host, SpfLimits $limits, array &$ip4, array &$ip6, array &$errors): void
    {
        if (! $limits->charge()) {
            $errors[] = 'exceeded the RFC 7208 lookup limit at mx: '.$host;

            return;
        }

        $exchanges = $this->values(strtolower(rtrim($host, '.')), RecordType::MX);

        if ($exchanges === []) {
            $limits->voidLookups++;

            return;
        }

        // RFC 7208 §4.6.4: an mx resolving to more than 10 MX records is a permerror.
        if (count($exchanges) > 10) {
            $errors[] = "mx:{$host} resolves to more than 10 MX records (RFC 7208 limit)";

            return;
        }

        foreach ($exchanges as $exchange) {
            $exchange = strtolower(rtrim($exchange, '.'));

            foreach ($this->values($exchange, RecordType::A) as $ip) {
                $ip4[] = $ip;
            }

            foreach ($this->values($exchange, RecordType::AAAA) as $ip) {
                $ip6[] = $ip;
            }
        }
    }

    /**
     * @param  list<string>  $path
     * @param  list<SpfEvaluation>  $includes
     * @param  list<string>  $errors
     */
    private function expandInclude(?string $target, SpfLimits $limits, array $path, array &$includes, array &$errors): void
    {
        if ($target === null || $target === '') {
            $errors[] = 'include: mechanism has no domain';

            return;
        }

        if (! $limits->charge()) {
            $errors[] = 'exceeded the RFC 7208 lookup limit at include: '.$target;

            return;
        }

        $includes[] = $this->evaluate(strtolower(rtrim($target, '.')), $limits, $path);
    }

    private function fetchSpf(string $domain, SpfLimits $limits): ?string
    {
        $records = $this->values($domain, RecordType::TXT);

        if ($records === []) {
            $limits->voidLookups++;
        }

        foreach ($records as $txt) {
            if (preg_match('/^v=spf1(\s|$)/i', trim($txt))) {
                return trim($txt);
            }
        }

        return null;
    }

    /**
     * @return list<string>
     */
    private function values(string $host, RecordType $type): array
    {
        try {
            return $this->resolver->query($host, $type)->values();
        } catch (DnsException) {
            return [];
        }
    }

    private function error(string $domain, ?string $record, SpfLimits $limits, string $error): SpfEvaluation
    {
        return new SpfEvaluation($domain, $record, [], [], [], null, null, $limits->lookups, $limits->exceeded(), [$error]);
    }
}
