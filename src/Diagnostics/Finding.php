<?php

declare(strict_types=1);

namespace Cbox\Dns\Diagnostics;

use Cbox\Dns\Diagnostics\Enums\Severity;

/**
 * One observation from a diagnostic check: its {@see Severity}, the `category` it
 * belongs to (e.g. "Nameservers", "Email"), the `check` that produced it, a
 * human-readable `message`, and a machine-readable `context` bag for the raw
 * values behind the message (the record sets, IPs, serials, …).
 */
final readonly class Finding
{
    /**
     * @param  array<string, mixed>  $context
     */
    public function __construct(
        public Severity $severity,
        public string $category,
        public string $check,
        public string $message,
        public array $context = [],
    ) {}

    /**
     * @param  array<string, mixed>  $context
     */
    public static function error(string $category, string $check, string $message, array $context = []): self
    {
        return new self(Severity::Error, $category, $check, $message, $context);
    }

    /**
     * @param  array<string, mixed>  $context
     */
    public static function warning(string $category, string $check, string $message, array $context = []): self
    {
        return new self(Severity::Warning, $category, $check, $message, $context);
    }

    /**
     * @param  array<string, mixed>  $context
     */
    public static function info(string $category, string $check, string $message, array $context = []): self
    {
        return new self(Severity::Info, $category, $check, $message, $context);
    }
}
