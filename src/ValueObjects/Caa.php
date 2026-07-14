<?php

declare(strict_types=1);

namespace Cbox\Dns\ValueObjects;

use Cbox\Dns\Contracts\RecordData;

/**
 * A parsed CAA record (RFC 8659). The decoders render a CAA as `flags tag "value"`
 * on {@see DnsRecord::$value}; this value object turns that back into typed fields.
 */
readonly class Caa implements RecordData
{
    public function __construct(
        public int $flags,
        public string $tag,
        public string $value,
    ) {}

    /**
     * True when the critical bit (0x80) is set — an unrecognised critical property
     * must be treated as a hard failure by a certificate authority (RFC 8659 §4.1).
     */
    public function isCritical(): bool
    {
        return ($this->flags & 0x80) !== 0;
    }

    /**
     * Parse the `flags tag "value"` presentation form, or null if malformed.
     */
    public static function fromPresentation(string $value): ?self
    {
        if (! preg_match('/^\s*(\d+)\s+(\S+)\s+"(.*)"\s*$/s', $value, $m)) {
            return null;
        }

        return new self((int) $m[1], $m[2], $m[3]);
    }

    public function presentation(): string
    {
        return "{$this->flags} {$this->tag} \"{$this->value}\"";
    }
}
