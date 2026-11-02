<?php

declare(strict_types=1);

namespace Cbox\Dns\DomainConnect;

use Cbox\Dns\DomainConnect\Enums\Essential;
use Cbox\Dns\DomainConnect\Enums\TemplateRecordType;
use Cbox\Dns\DomainConnect\Enums\TxtConflictMatchingMode;
use Cbox\Dns\DomainConnect\Exceptions\InvalidTemplate;

/**
 * One record of a Domain Connect template. Values may contain %variable%
 * placeholders that the service provider fills in per request.
 */
readonly class TemplateRecord
{
    public function __construct(
        public TemplateRecordType $type,
        public string $host,
        public ?string $pointsTo = null,
        public ?string $data = null,
        public ?string $spfRules = null,
        public ?int $ttl = null,
        public ?int $priority = null,
        public ?string $groupId = null,
        public Essential $essential = Essential::Always,
        public TxtConflictMatchingMode $txtConflictMatchingMode = TxtConflictMatchingMode::None,
        public ?string $txtConflictMatchingPrefix = null,
    ) {}

    /**
     * @param  array<string, mixed>  $data
     */
    public static function fromArray(array $data): self
    {
        $typeName = self::string($data, 'type');
        $type = TemplateRecordType::tryFrom($typeName)
            ?? throw InvalidTemplate::because("unknown record type [{$typeName}]");

        $essential = self::optionalString($data, 'essential');
        $mode = self::optionalString($data, 'txtConflictMatchingMode');

        return new self(
            type: $type,
            host: self::string($data, 'host'),
            pointsTo: self::optionalString($data, 'pointsTo'),
            data: self::optionalString($data, 'data'),
            spfRules: self::optionalString($data, 'spfRules'),
            ttl: self::optionalInt($data, 'ttl'),
            priority: self::optionalInt($data, 'priority'),
            groupId: self::optionalString($data, 'groupId'),
            essential: $essential === null
                ? Essential::Always
                : (Essential::tryFrom($essential) ?? throw InvalidTemplate::because("unknown essential value [{$essential}]")),
            txtConflictMatchingMode: $mode === null
                ? TxtConflictMatchingMode::None
                : (TxtConflictMatchingMode::tryFrom($mode) ?? throw InvalidTemplate::because("unknown txtConflictMatchingMode [{$mode}]")),
            txtConflictMatchingPrefix: self::optionalString($data, 'txtConflictMatchingPrefix'),
        );
    }

    /**
     * Null fields and the defaults for essential / txtConflictMatchingMode are omitted.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        $out = [];

        if ($this->groupId !== null) {
            $out['groupId'] = $this->groupId;
        }

        $out['type'] = $this->type->value;
        $out['host'] = $this->host;

        foreach (['pointsTo' => $this->pointsTo, 'data' => $this->data, 'spfRules' => $this->spfRules, 'priority' => $this->priority, 'ttl' => $this->ttl] as $key => $value) {
            if ($value !== null) {
                $out[$key] = $value;
            }
        }

        if ($this->txtConflictMatchingMode !== TxtConflictMatchingMode::None) {
            $out['txtConflictMatchingMode'] = $this->txtConflictMatchingMode->value;
        }

        if ($this->txtConflictMatchingPrefix !== null) {
            $out['txtConflictMatchingPrefix'] = $this->txtConflictMatchingPrefix;
        }

        if ($this->essential !== Essential::Always) {
            $out['essential'] = $this->essential->value;
        }

        return $out;
    }

    /** Variables the DNS provider fills in itself; never supplied by the caller. */
    public const array BUILT_IN_VARIABLES = ['domain', 'host', 'fqdn'];

    /**
     * Variable names used in host, pointsTo, data and spfRules, in order of
     * first appearance, without the built-ins `%domain%`, `%host%` and `%fqdn%`.
     *
     * @return list<string>
     */
    public function variables(): array
    {
        $names = [];

        foreach ([$this->host, $this->pointsTo, $this->data, $this->spfRules] as $value) {
            if ($value !== null && preg_match_all('/%([a-z0-9_]+)%/i', $value, $matches) > 0) {
                foreach ($matches[1] as $name) {
                    if (! in_array(strtolower($name), self::BUILT_IN_VARIABLES, true)) {
                        $names[] = $name;
                    }
                }
            }
        }

        return array_values(array_unique($names));
    }

    /**
     * @param  array<string, mixed>  $data
     */
    private static function string(array $data, string $key): string
    {
        $value = $data[$key] ?? null;

        if (! is_string($value)) {
            throw InvalidTemplate::because("record field [{$key}] must be a string");
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
     * @param  array<string, mixed>  $data
     */
    private static function optionalInt(array $data, string $key): ?int
    {
        $value = $data[$key] ?? null;

        if ($value === null) {
            return null;
        }

        if (! is_int($value)) {
            throw InvalidTemplate::because("record field [{$key}] must be an integer");
        }

        return $value;
    }
}
