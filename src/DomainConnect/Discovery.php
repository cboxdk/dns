<?php

declare(strict_types=1);

namespace Cbox\Dns\DomainConnect;

use Cbox\Dns\DomainConnect\Exceptions\InvalidPayload;
use DateTimeImmutable;
use Exception;

/**
 * The result of checking whether a zone's DNS provider speaks Domain Connect,
 * and whether it supports our template.
 */
readonly class Discovery
{
    public function __construct(
        public Zone $zone,
        public ?ProviderSettings $settings,
        public ?bool $supported,
        public DateTimeImmutable $checkedAt,
    ) {}

    /**
     * The provider speaks Domain Connect and offers the synchronous flow.
     */
    public function isAvailable(): bool
    {
        return $this->settings?->supportsSync() ?? false;
    }

    public function supportsTemplate(): bool
    {
        return $this->supported === true;
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'apex' => $this->zone->apex,
            'host' => $this->zone->host,
            'settings' => $this->settings?->toArray(),
            'supported' => $this->supported,
            'checkedAt' => $this->checkedAt->format(DATE_ATOM),
        ];
    }

    /**
     * @param  array<string, mixed>  $data
     */
    public static function fromArray(array $data): self
    {
        $apex = $data['apex'] ?? null;
        $host = $data['host'] ?? null;
        $settings = $data['settings'] ?? null;
        $supported = $data['supported'] ?? null;
        $checkedAt = $data['checkedAt'] ?? null;

        if (! is_string($apex) || ! is_string($host)) {
            throw InvalidPayload::because('discovery fields [apex] and [host] must be strings');
        }

        if ($settings !== null && ! is_array($settings)) {
            throw InvalidPayload::because('discovery field [settings] must be an array or null');
        }

        $settingsData = [];

        foreach ($settings ?? [] as $key => $value) {
            if (! is_string($key)) {
                throw InvalidPayload::because('discovery field [settings] must be keyed by strings');
            }

            $settingsData[$key] = $value;
        }

        if ($supported !== null && ! is_bool($supported)) {
            throw InvalidPayload::because('discovery field [supported] must be a boolean or null');
        }

        if (! is_string($checkedAt)) {
            throw InvalidPayload::because('discovery field [checkedAt] must be a string');
        }

        try {
            $when = new DateTimeImmutable($checkedAt);
        } catch (Exception) {
            throw InvalidPayload::because('discovery field [checkedAt] is not a valid date');
        }

        return new self(
            Zone::of($apex, $host),
            $settings === null ? null : ProviderSettings::fromArray($settingsData),
            $supported,
            $when,
        );
    }
}
