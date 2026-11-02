<?php

declare(strict_types=1);

namespace Cbox\Dns\DomainConnect;

use Cbox\Dns\Contracts\Resolver;
use Cbox\Dns\Dnssec\Contracts\Clock;
use Cbox\Dns\Dnssec\Support\SystemClock;
use Cbox\Dns\DomainConnect\Contracts\Transport;
use Cbox\Dns\DomainConnect\Exceptions\DiscoveryRefused;
use Cbox\Dns\DomainConnect\Exceptions\InvalidPayload;
use Cbox\Dns\DomainConnect\Exceptions\ZoneNotFound;
use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Exceptions\DnsException;
use Cbox\Dns\Support\IpAddress;
use DateTimeImmutable;

/**
 * Finds whether a name's DNS provider speaks Domain Connect (via the zone's
 * `_domainconnect` TXT record and the provider's settings document) and, given
 * a template, whether the provider knows it.
 *
 * Both URLs fetched come from data others control, so each is parsed the way
 * the transport will parse it, must be plain https (no userinfo, query or
 * fragment, a hostname or IP literal host), and, unless `allowNonPublicHosts`,
 * its host must resolve to public addresses only. The request is then pinned to
 * the address that passed the check. A failed lookup fails closed: no request.
 */
class Discoverer
{
    public function __construct(
        private readonly Resolver $resolver,
        private readonly Transport $transport,
        private readonly ZoneLocator $zones,
        private readonly Clock $clock = new SystemClock,
        private readonly bool $allowNonPublicHosts = false,
    ) {}

    /**
     * @throws ZoneNotFound when no zone apex can be found for the name
     * @throws DiscoveryRefused when the `_domainconnect` record is not safe to follow
     */
    public function discover(string $name, ?Template $template = null): Discovery
    {
        $zone = $this->zones->locate($name);
        $settings = $this->settings($zone->apex);
        $supported = $settings === null || $template === null ? null : $this->supports($zone->apex, $settings, $template);

        return new Discovery($zone, $settings, $supported, new DateTimeImmutable('@'.$this->clock->now()));
    }

    /**
     * @throws DiscoveryRefused
     */
    private function settings(string $apex): ?ProviderSettings
    {
        $value = trim($this->values("_domainconnect.{$apex}", RecordType::TXT)[0] ?? '');

        if ($value === '') {
            return null;
        }

        if (preg_match('/\s/', $value) === 1) {
            throw DiscoveryRefused::because($apex, 'the _domainconnect value contains whitespace');
        }

        if (str_contains($value, '://')) {
            if (strncasecmp($value, 'https://', 8) !== 0) {
                throw DiscoveryRefused::because($apex, 'the _domainconnect value uses a scheme other than https');
            }

            $value = substr($value, 8);
        }

        $url = 'https://'.rtrim($value, '/')."/v2/{$apex}/settings";
        $host = $this->safeHost($url);

        if ($host === null) {
            throw DiscoveryRefused::because($apex, 'the _domainconnect value is not a plain https host, host:port or host/path');
        }

        $response = $this->fetch($apex, $url, $host);
        $data = $response !== null && $response->ok() ? $response->json() : null;

        if ($data === null) {
            return null;
        }

        try {
            return ProviderSettings::fromArray($data);
        } catch (InvalidPayload) {
            return null;
        }
    }

    private function supports(string $apex, ProviderSettings $settings, Template $template): ?bool
    {
        if ($settings->urlAPI === null) {
            return null;
        }

        $url = rtrim($settings->urlAPI, '/')
            .'/v2/domainTemplates/providers/'.rawurlencode($template->providerId)
            .'/services/'.rawurlencode($template->serviceId);
        $host = $this->safeHost($url);

        if ($host === null) {
            return null;
        }

        try {
            $response = $this->fetch($apex, $url, $host);
        } catch (DiscoveryRefused) {
            return null; // the provider was found; an unsafe API host only leaves support unknown
        }

        return match (true) {
            $response === null => null,
            $response->ok() => true,
            $response->status === 404 => false,
            default => null,
        };
    }

    /**
     * The host of an https URL with no userinfo, query or fragment, whose host is
     * a hostname or (bracketed) IP literal; brackets stripped. Null otherwise.
     */
    private function safeHost(string $url): ?string
    {
        $parts = parse_url($url);

        if (! is_array($parts)
            || strtolower($parts['scheme'] ?? '') !== 'https'
            || isset($parts['user']) || isset($parts['pass']) || isset($parts['query']) || isset($parts['fragment'])
        ) {
            return null;
        }

        $host = $parts['host'] ?? '';

        if (preg_match('/^\[(.+)\]$/', $host, $m) === 1) {
            return filter_var($m[1], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false ? $m[1] : null;
        }

        return preg_match('/^[A-Za-z0-9.-]+$/', $host) === 1 ? $host : null;
    }

    /**
     * GET the URL pinned to a validated public address of its host; null (no
     * request) when the host has no address or a lookup fails.
     *
     * @throws DiscoveryRefused when the host has a non-public address
     */
    private function fetch(string $apex, string $url, string $host): ?HttpResponse
    {
        if ($this->allowNonPublicHosts) {
            return $this->transport->get($url);
        }

        $peer = $this->publicPeer($apex, $host);

        return $peer === null ? null : $this->transport->get($url, $peer);
    }

    /**
     * The address to pin to (an A record preferred over AAAA), or null when the
     * host has none or either lookup fails (fail closed: a failed family is not
     * skipped in favour of the other).
     *
     * @throws DiscoveryRefused when any address is non-public
     */
    private function publicPeer(string $apex, string $host): ?string
    {
        if (IpAddress::isIp($host)) {
            $addresses = [$host];
        } else {
            $v4 = $this->values($host, RecordType::A);
            $v6 = $v4 === null ? null : $this->values($host, RecordType::AAAA);

            if ($v4 === null || $v6 === null) {
                return null;
            }

            $addresses = [...$v4, ...$v6];
        }

        foreach ($addresses as $address) {
            if (! IpAddress::isPublic($address)) {
                throw DiscoveryRefused::because($apex, "the host [{$host}] resolves to the non-public address [{$address}]");
            }
        }

        return $addresses[0] ?? null;
    }

    /**
     * The values of the answer records of exactly `$type` (a CNAME in the
     * answer is skipped), or null when the lookup failed: it threw, or the
     * server answered with an error code other than NXDOMAIN.
     *
     * @return list<string>|null
     */
    private function values(string $host, RecordType $type): ?array
    {
        try {
            $response = $this->resolver->query($host, $type);
        } catch (DnsException) {
            return null;
        }

        if (! $response->succeeded() && ! $response->isNxDomain()) {
            return null;
        }

        $values = [];

        foreach ($response->records as $record) {
            if ($record->type === $type) {
                $values[] = $record->value;
            }
        }

        return $values;
    }
}
