<?php

declare(strict_types=1);

namespace Cbox\Dns\ValueObjects;

/**
 * One term of an SPF policy (RFC 7208 §5) — a qualifier, a mechanism name, and its
 * optional value. For example `-all` is `{qualifier: '-', name: 'all'}` and
 * `include:_spf.google.com` is `{qualifier: '+', name: 'include', value: '_spf.google.com'}`.
 */
readonly class SpfMechanism
{
    public function __construct(
        public string $qualifier,
        public string $name,
        public ?string $value = null,
    ) {}

    /**
     * Whether this is a Fail (`-`), SoftFail (`~`), Neutral (`?`), or Pass (`+`)
     * result, spelled out.
     */
    public function result(): string
    {
        return match ($this->qualifier) {
            '-' => 'fail',
            '~' => 'softfail',
            '?' => 'neutral',
            default => 'pass',
        };
    }
}
