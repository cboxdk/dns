<?php

declare(strict_types=1);

namespace Cbox\Dns\DomainConnect;

use Cbox\Dns\DomainConnect\Exceptions\InvalidTemplate;
use JsonException;

/**
 * A Domain Connect template: the set of DNS records a service provider asks a
 * DNS host to apply to a customer's domain.
 */
readonly class Template
{
    /**
     * @param  list<TemplateRecord>  $records
     */
    public function __construct(
        public string $providerId,
        public string $providerName,
        public string $serviceId,
        public string $serviceName,
        public int $version,
        public array $records,
        public ?string $syncPubKeyDomain = null,
        public ?string $syncRedirectDomain = null,
        public bool $syncBlock = false,
        public ?string $logoUrl = null,
        public ?string $description = null,
        public ?string $variableDescription = null,
    ) {}

    public static function fromJson(string $json): self
    {
        try {
            $decoded = json_decode($json, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw InvalidTemplate::because('not valid JSON ('.$e->getMessage().')');
        }

        return self::fromArray(self::object($decoded, 'the JSON document'));
    }

    /**
     * @param  array<string, mixed>  $data
     */
    public static function fromArray(array $data): self
    {
        $rawRecords = $data['records'] ?? null;

        if (! is_array($rawRecords) || ! array_is_list($rawRecords)) {
            throw InvalidTemplate::because('field [records] must be a list');
        }

        $records = [];

        foreach ($rawRecords as $raw) {
            $records[] = TemplateRecord::fromArray(self::object($raw, 'every entry in [records]'));
        }

        $version = $data['version'] ?? null;

        if (! is_int($version)) {
            throw InvalidTemplate::because('field [version] must be an integer');
        }

        $syncBlock = $data['syncBlock'] ?? false;

        if (! is_bool($syncBlock)) {
            throw InvalidTemplate::because('field [syncBlock] must be a boolean');
        }

        return new self(
            providerId: self::string($data, 'providerId'),
            providerName: self::string($data, 'providerName'),
            serviceId: self::string($data, 'serviceId'),
            serviceName: self::string($data, 'serviceName'),
            version: $version,
            records: $records,
            syncPubKeyDomain: self::optionalString($data, 'syncPubKeyDomain'),
            syncRedirectDomain: self::optionalString($data, 'syncRedirectDomain'),
            syncBlock: $syncBlock,
            logoUrl: self::optionalString($data, 'logoUrl'),
            description: self::optionalString($data, 'description'),
            variableDescription: self::optionalString($data, 'variableDescription'),
        );
    }

    /**
     * Always emits syncBlock; omits other fields that are null.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        $out = [
            'providerId' => $this->providerId,
            'providerName' => $this->providerName,
            'serviceId' => $this->serviceId,
            'serviceName' => $this->serviceName,
            'version' => $this->version,
        ];

        foreach (['logoUrl' => $this->logoUrl, 'description' => $this->description] as $key => $value) {
            if ($value !== null) {
                $out[$key] = $value;
            }
        }

        $out['syncBlock'] = $this->syncBlock;

        foreach ([
            'syncPubKeyDomain' => $this->syncPubKeyDomain,
            'syncRedirectDomain' => $this->syncRedirectDomain,
            'variableDescription' => $this->variableDescription,
        ] as $key => $value) {
            if ($value !== null) {
                $out[$key] = $value;
            }
        }

        $out['records'] = array_map(static fn (TemplateRecord $record): array => $record->toArray(), $this->records);

        return $out;
    }

    /**
     * Variable names used by any record, in order of first appearance.
     *
     * @return list<string>
     */
    public function variables(): array
    {
        $names = [];

        foreach ($this->records as $record) {
            foreach ($record->variables() as $name) {
                $names[] = $name;
            }
        }

        return array_values(array_unique($names));
    }

    /**
     * Group ids used by any record, in order of first appearance.
     *
     * @return list<string>
     */
    public function groupIds(): array
    {
        $ids = [];

        foreach ($this->records as $record) {
            if ($record->groupId !== null) {
                $ids[] = $record->groupId;
            }
        }

        return array_values(array_unique($ids));
    }

    /**
     * @return array<string, mixed>
     */
    private static function object(mixed $value, string $what): array
    {
        if (! is_array($value)) {
            throw InvalidTemplate::because("{$what} must be an object");
        }

        $object = [];

        foreach ($value as $key => $item) {
            if (! is_string($key)) {
                throw InvalidTemplate::because("{$what} must be an object");
            }

            $object[$key] = $item;
        }

        return $object;
    }

    /**
     * @param  array<string, mixed>  $data
     */
    private static function string(array $data, string $key): string
    {
        $value = $data[$key] ?? null;

        if (! is_string($value)) {
            throw InvalidTemplate::because("field [{$key}] must be a string");
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
}
