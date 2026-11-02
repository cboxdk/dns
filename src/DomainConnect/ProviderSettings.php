<?php

declare(strict_types=1);

namespace Cbox\Dns\DomainConnect;

use Cbox\Dns\DomainConnect\Exceptions\InvalidPayload;
use Cbox\Dns\DomainConnect\Support\HttpsUrl;

/**
 * A DNS provider's Domain Connect settings document
 * (https://_domainconnect.<domain>/v2/<domain>/settings).
 *
 * {@see self::fromArray()} reads an untrusted document, so each URL field, when
 * present, must be plain https (a host; no userinfo, query or fragment) or the
 * payload is refused with {@see InvalidPayload}.
 */
readonly class ProviderSettings
{
    /**
     * @param  list<string>  $nameServers
     */
    public function __construct(
        public string $providerId,
        public string $providerName,
        public ?string $urlSyncUX = null,
        public ?string $urlAsyncUX = null,
        public ?string $urlAPI = null,
        public ?string $urlControlPanel = null,
        public int $width = 750,
        public int $height = 750,
        public array $nameServers = [],
    ) {}

    /**
     * @param  array<string, mixed>  $data
     */
    public static function fromArray(array $data): self
    {
        return new self(
            providerId: self::string($data, 'providerId'),
            providerName: self::string($data, 'providerName'),
            urlSyncUX: self::optionalUrl($data, 'urlSyncUX'),
            urlAsyncUX: self::optionalUrl($data, 'urlAsyncUX'),
            urlAPI: self::optionalUrl($data, 'urlAPI'),
            urlControlPanel: self::optionalUrl($data, 'urlControlPanel'),
            width: self::int($data, 'width', 750),
            height: self::int($data, 'height', 750),
            nameServers: self::stringList($data, 'nameServers'),
        );
    }

    /**
     * Null fields are omitted.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        $out = ['providerId' => $this->providerId, 'providerName' => $this->providerName];

        foreach (['urlSyncUX' => $this->urlSyncUX, 'urlAsyncUX' => $this->urlAsyncUX, 'urlAPI' => $this->urlAPI, 'urlControlPanel' => $this->urlControlPanel] as $key => $value) {
            if ($value !== null) {
                $out[$key] = $value;
            }
        }

        $out['width'] = $this->width;
        $out['height'] = $this->height;

        if ($this->nameServers !== []) {
            $out['nameServers'] = $this->nameServers;
        }

        return $out;
    }

    public function supportsSync(): bool
    {
        return $this->urlSyncUX !== null;
    }

    /**
     * @param  array<string, mixed>  $data
     */
    private static function string(array $data, string $key): string
    {
        $value = $data[$key] ?? null;

        if (! is_string($value)) {
            throw InvalidPayload::because("provider settings field [{$key}] must be a string");
        }

        return $value;
    }

    /**
     * @param  array<string, mixed>  $data
     */
    private static function optionalString(array $data, string $key): ?string
    {
        return ($data[$key] ?? null) === null ? null : self::string($data, $key);
    }

    /**
     * An optional URL from the (untrusted) settings document: when present it
     * must be plain https (a host, no userinfo, query or fragment).
     *
     * @param  array<string, mixed>  $data
     */
    private static function optionalUrl(array $data, string $key): ?string
    {
        $value = self::optionalString($data, $key);

        if ($value !== null && ! HttpsUrl::isPlain($value)) {
            throw InvalidPayload::because("provider settings field [{$key}] must be a plain https URL");
        }

        return $value;
    }

    /**
     * @param  array<string, mixed>  $data
     */
    private static function int(array $data, string $key, int $default): int
    {
        $value = $data[$key] ?? $default;

        if (! is_int($value)) {
            throw InvalidPayload::because("provider settings field [{$key}] must be an integer");
        }

        return $value;
    }

    /**
     * @param  array<string, mixed>  $data
     * @return list<string>
     */
    private static function stringList(array $data, string $key): array
    {
        $value = $data[$key] ?? [];

        if (! is_array($value)) {
            throw InvalidPayload::because("provider settings field [{$key}] must be a list of strings");
        }

        $out = [];

        foreach ($value as $item) {
            if (! is_string($item)) {
                throw InvalidPayload::because("provider settings field [{$key}] must be a list of strings");
            }

            $out[] = $item;
        }

        return $out;
    }
}
