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
 * The `_domainconnect` value is attacker-influenced, so it is only fetched over
 * https and only when its host resolves to public addresses (unless
 * `allowNonPublicHosts`). Failures to find or read the provider are reported as
 * a Discovery without settings, never as an exception.
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
        $base = $this->discoveryBase($zone->apex);
        $settings = $base === null ? null : $this->settings("https://{$base}/v2/{$zone->apex}/settings");
        $supported = $settings === null || $template === null ? null : $this->supports($settings, $template);

        return new Discovery($zone, $settings, $supported, new DateTimeImmutable('@'.$this->clock->now()));
    }

    /**
     * The `_domainconnect` value without scheme or trailing slash, or null when
     * there is none or its host has no address.
     */
    private function discoveryBase(string $apex): ?string
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

        $value = rtrim($value, '/');

        if ($value === '') {
            return null;
        }

        if (! $this->allowNonPublicHosts && ! $this->hostIsPublic($apex, $value)) {
            return null;
        }

        return $value;
    }

    /**
     * Whether the value's host resolves to public addresses only; false when it
     * resolves to none.
     *
     * @throws DiscoveryRefused when any address is non-public
     */
    private function hostIsPublic(string $apex, string $value): bool
    {
        $host = explode('/', $value, 2)[0];
        $host = explode(':', $host, 2)[0];

        $addresses = IpAddress::isIp($host) ? [$host] : [...$this->values($host, RecordType::A), ...$this->values($host, RecordType::AAAA)];

        foreach ($addresses as $address) {
            if (! IpAddress::isPublic($address)) {
                throw DiscoveryRefused::because($apex, "the discovery host [{$host}] resolves to the non-public address [{$address}]");
            }
        }

        return $addresses !== [];
    }

    /**
     * The values of the answer records of exactly `$type` (a CNAME in the answer
     * is skipped); none when the lookup fails.
     *
     * @return list<string>
     */
    private function values(string $host, RecordType $type): array
    {
        try {
            $records = $this->resolver->query($host, $type)->records;
        } catch (DnsException) {
            return [];
        }

        $values = [];

        foreach ($records as $record) {
            if ($record->type === $type) {
                $values[] = $record->value;
            }
        }

        return $values;
    }

    private function settings(string $url): ?ProviderSettings
    {
        $response = $this->transport->get($url);
        $data = $response->ok() ? $response->json() : null;

        if ($data === null) {
            return null;
        }

        try {
            return ProviderSettings::fromArray($data);
        } catch (InvalidPayload) {
            return null;
        }
    }

    private function supports(ProviderSettings $settings, Template $template): ?bool
    {
        if ($settings->urlAPI === null || strncasecmp($settings->urlAPI, 'https://', 8) !== 0) {
            return null;
        }

        $url = rtrim($settings->urlAPI, '/')
            .'/v2/domainTemplates/providers/'.rawurlencode($template->providerId)
            .'/services/'.rawurlencode($template->serviceId);

        $response = $this->transport->get($url);

        return match (true) {
            $response->ok() => true,
            $response->status === 404 => false,
            default => null,
        };
    }
}
