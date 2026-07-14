<?php

declare(strict_types=1);

namespace Cbox\Dns\ValueObjects;

use Cbox\Dns\Support\TagString;

/**
 * A parsed DKIM key record (RFC 6376 §3.6.1) from a `…_domainkey` TXT record: the
 * key type (default `rsa`), the base64 public key, the permitted hash algorithms,
 * service types, and flags. An empty public key (`p=`) means the key was revoked.
 */
readonly class DkimKey
{
    /**
     * @param  list<string>  $hashAlgorithms  the `h=` list (empty = all allowed)
     * @param  list<string>  $serviceTypes  the `s=` list (empty = `*`)
     * @param  list<string>  $flags  the `t=` flag list (e.g. `y` test, `s` strict)
     */
    public function __construct(
        public string $keyType,
        public string $publicKey,
        public ?string $version = null,
        public array $hashAlgorithms = [],
        public array $serviceTypes = [],
        public array $flags = [],
        public ?string $notes = null,
    ) {}

    /**
     * Whether the key has been revoked — a published record with an empty `p=` tag.
     */
    public function isRevoked(): bool
    {
        return $this->publicKey === '';
    }

    /**
     * Whether the domain is in DKIM test mode (`t=y`).
     */
    public function isTesting(): bool
    {
        return in_array('y', $this->flags, true);
    }

    /**
     * Parse a TXT string as a DKIM key, or null if it is not one (it must carry a
     * `p=` public-key tag, optionally with `v=DKIM1`).
     */
    public static function parse(string $txt): ?self
    {
        $tags = TagString::parse($txt);

        if (! array_key_exists('p', $tags)) {
            return null;
        }

        if (isset($tags['v']) && strcasecmp($tags['v'], 'DKIM1') !== 0) {
            return null;
        }

        return new self(
            $tags['k'] ?? 'rsa',
            preg_replace('/\s+/', '', $tags['p']) ?? '',
            $tags['v'] ?? null,
            self::list($tags['h'] ?? null),
            self::list($tags['s'] ?? null),
            self::list($tags['t'] ?? null),
            $tags['n'] ?? null,
        );
    }

    /**
     * @return list<string>
     */
    private static function list(?string $value): array
    {
        if ($value === null || trim($value) === '') {
            return [];
        }

        return array_values(array_filter(array_map('trim', explode(':', $value)), static fn (string $v): bool => $v !== ''));
    }
}
