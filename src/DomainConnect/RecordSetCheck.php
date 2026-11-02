<?php

declare(strict_types=1);

namespace Cbox\Dns\DomainConnect;

use Cbox\Dns\Diagnostics\Contracts\Check;
use Cbox\Dns\Diagnostics\DiagnosticContext;
use Cbox\Dns\Diagnostics\Finding;
use Cbox\Dns\DomainConnect\Enums\TemplateRecordType;
use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Exceptions\DnsException;
use Cbox\Dns\ValueObjects\DnsRecord;

/**
 * Compares the records a template expects against what the zone's authoritative
 * nameservers actually serve: one finding per expected record, in RecordSet order.
 */
class RecordSetCheck implements Check
{
    private const string CATEGORY = 'DomainConnect';

    public function __construct(
        private readonly RecordSet $set,
    ) {}

    public function run(DiagnosticContext $ctx): array
    {
        $findings = [];

        foreach ($this->set->records as $expected) {
            $findings[] = $this->check($ctx, $expected);
        }

        return $findings;
    }

    private function check(DiagnosticContext $ctx, ExpectedRecord $expected): Finding
    {
        if ($expected->type === TemplateRecordType::SRV) {
            return Finding::info(self::CATEGORY, 'domain-connect.skipped', 'SRV records are not checked.', [
                'name' => $expected->name,
                'type' => $expected->type->value,
            ]);
        }

        $isMx = $expected->type === TemplateRecordType::MX;

        try {
            $records = $ctx->authoritative->query($expected->name, $this->queryType($expected->type), $this->set->zone->apex)->records;
        } catch (DnsException) {
            $records = [];
        }

        $live = array_map(fn (DnsRecord $record): string => $isMx ? "{$record->priority} ".$this->normaliseName($record->value) : $record->value, $records);
        $shownExpected = $isMx ? "{$expected->priority} ".$this->normaliseName($expected->value) : $expected->value;

        $context = [
            'name' => $expected->name,
            'type' => $expected->type->value,
            'expected' => $shownExpected,
            'live' => $live,
        ];

        if ($records === []) {
            return Finding::error(self::CATEGORY, 'domain-connect.missing', "{$expected->type->value} {$expected->name} is not published.", $context);
        }

        if ($this->matches($expected, $records)) {
            return Finding::info(self::CATEGORY, 'domain-connect.present', "{$expected->type->value} {$expected->name} is published as expected.", $context);
        }

        return Finding::error(self::CATEGORY, 'domain-connect.mismatch', "{$expected->type->value} {$expected->name} is published with a different value.", $context);
    }

    /**
     * @param  non-empty-list<DnsRecord>  $records
     */
    private function matches(ExpectedRecord $expected, array $records): bool
    {
        // The decoder already joins a TXT record's character-strings into one value.
        foreach ($records as $record) {
            $matched = match ($expected->type) {
                TemplateRecordType::TXT => trim($record->value) === trim($expected->value),
                TemplateRecordType::MX => $record->priority === $expected->priority
                    && $this->normaliseName($record->value) === $this->normaliseName($expected->value),
                TemplateRecordType::CNAME, TemplateRecordType::NS, TemplateRecordType::APEXCNAME => $this->normaliseName($record->value) === $this->normaliseName($expected->value),
                TemplateRecordType::SPFM => $this->spfContains($record->value, $expected->value),
                TemplateRecordType::A, TemplateRecordType::AAAA => $record->value === $expected->value,
                TemplateRecordType::SRV => false,
            };

            if ($matched) {
                return true;
            }
        }

        return false;
    }

    private function spfContains(string $spf, string $rules): bool
    {
        if (! str_starts_with(strtolower(ltrim($spf)), 'v=spf1')) {
            return false;
        }

        $terms = preg_split('/\s+/', trim($spf), -1, PREG_SPLIT_NO_EMPTY);
        $wanted = preg_split('/\s+/', trim($rules), -1, PREG_SPLIT_NO_EMPTY);

        if ($terms === false || $wanted === false) {
            return false;
        }

        return array_diff($wanted, $terms) === [];
    }

    private function normaliseName(string $name): string
    {
        return rtrim(strtolower($name), '.');
    }

    private function queryType(TemplateRecordType $type): RecordType
    {
        return match ($type) {
            TemplateRecordType::A => RecordType::A,
            TemplateRecordType::AAAA => RecordType::AAAA,
            TemplateRecordType::CNAME, TemplateRecordType::APEXCNAME => RecordType::CNAME,
            TemplateRecordType::NS => RecordType::NS,
            TemplateRecordType::MX => RecordType::MX,
            TemplateRecordType::TXT, TemplateRecordType::SPFM, TemplateRecordType::SRV => RecordType::TXT,
        };
    }
}
