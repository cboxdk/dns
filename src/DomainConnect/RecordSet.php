<?php

declare(strict_types=1);

namespace Cbox\Dns\DomainConnect;

use Cbox\Dns\DomainConnect\Enums\TemplateRecordType;
use Cbox\Dns\DomainConnect\Exceptions\InvalidApplyRequest;

/**
 * The records a zone should carry once a template is applied with a set of
 * variables: every %variable% substituted, every host made absolute.
 */
readonly class RecordSet
{
    /**
     * @param  list<ExpectedRecord>  $records
     */
    public function __construct(
        public Zone $zone,
        public array $records,
    ) {}

    /**
     * @param  array<string, string>  $variables  caller variables; the built-ins %domain%, %host% and %fqdn% come from the zone
     * @param  list<string>  $groupIds  empty means every record
     */
    public static function fromTemplate(Template $template, Zone $zone, array $variables, array $groupIds = []): self
    {
        $known = $template->variables();

        foreach (array_keys($variables) as $name) {
            if (! in_array($name, $known, true)) {
                throw InvalidApplyRequest::because("unknown variable [{$name}]");
            }
        }

        $defined = $template->groupIds();

        foreach ($groupIds as $groupId) {
            if (! in_array($groupId, $defined, true)) {
                throw InvalidApplyRequest::because("unknown group id [{$groupId}]");
            }
        }

        $records = [];

        foreach ($template->records as $record) {
            if ($groupIds !== [] && ! in_array($record->groupId, $groupIds, true)) {
                continue;
            }

            $records[] = self::expand($record, $zone, $variables);
        }

        return new self($zone, $records);
    }

    /**
     * @return list<array<string, mixed>>
     */
    public function toArray(): array
    {
        return array_map(static fn (ExpectedRecord $record): array => $record->toArray(), $this->records);
    }

    /**
     * @param  array<string, string>  $variables
     */
    private static function expand(TemplateRecord $record, Zone $zone, array $variables): ExpectedRecord
    {
        $type = $record->type;

        if ($type === TemplateRecordType::SRV) {
            throw InvalidApplyRequest::because('SRV records are not supported');
        }

        $host = $type === TemplateRecordType::APEXCNAME ? '@' : self::substitute($record->host, $zone, $variables);

        $value = match ($type) {
            TemplateRecordType::TXT => $record->data,
            TemplateRecordType::SPFM => $record->spfRules,
            default => $record->pointsTo,
        };

        if ($value === null) {
            $field = match ($type) {
                TemplateRecordType::TXT => 'data',
                TemplateRecordType::SPFM => 'spfRules',
                default => 'pointsTo',
            };

            throw InvalidApplyRequest::because("{$type->value} record at [{$record->host}] has no {$field}");
        }

        $value = self::substitute($value, $zone, $variables);

        if (in_array($type, [TemplateRecordType::CNAME, TemplateRecordType::NS, TemplateRecordType::MX, TemplateRecordType::APEXCNAME], true)) {
            $value = rtrim(strtolower($value), '.');
        }

        return new ExpectedRecord(
            type: $type,
            name: self::name($host, $zone),
            value: $value,
            priority: $record->priority,
            ttl: $record->ttl,
            groupId: $record->groupId,
        );
    }

    private static function name(string $host, Zone $zone): string
    {
        $host = trim($host);

        if ($host === '' || $host === '@') {
            $name = $zone->fqdn();
        } elseif (str_ends_with($host, '.')) {
            $name = $host;
        } else {
            $name = $host.'.'.$zone->fqdn();
        }

        return rtrim(strtolower($name), '.');
    }

    /**
     * Built-ins first, then the caller's variables; each pass is a single scan
     * so substituted values are never rescanned.
     *
     * @param  array<string, string>  $variables
     */
    private static function substitute(string $text, Zone $zone, array $variables): string
    {
        $builtIn = [
            'domain' => $zone->apex,
            'host' => $zone->host,
            'fqdn' => $zone->fqdn(),
        ];

        $text = (string) preg_replace_callback(
            '/%(domain|host|fqdn)%/i',
            static fn (array $m): string => $builtIn[strtolower($m[1])],
            $text,
        );

        return (string) preg_replace_callback(
            '/%([a-z0-9_]+)%/i',
            static fn (array $m): string => $variables[$m[1]]
                ?? throw InvalidApplyRequest::because("missing variable [{$m[1]}]"),
            $text,
        );
    }
}
