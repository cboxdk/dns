<?php

declare(strict_types=1);

namespace Cbox\Dns\DomainConnect;

use Cbox\Dns\DomainConnect\Enums\TemplateRecordType;

/**
 * One concrete record a zone should carry once a template is applied. For
 * SPFM the value is the SPF rules text.
 */
readonly class ExpectedRecord
{
    public function __construct(
        public TemplateRecordType $type,
        public string $name,
        public string $value,
        public ?int $priority = null,
        public ?int $ttl = null,
        public ?string $groupId = null,
    ) {}

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'type' => $this->type->value,
            'name' => $this->name,
            'value' => $this->value,
            'priority' => $this->priority,
            'ttl' => $this->ttl,
            'groupId' => $this->groupId,
        ];
    }
}
