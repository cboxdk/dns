<?php

declare(strict_types=1);

namespace Cbox\Dns\ValueObjects;

use Cbox\Dns\Contracts\RecordData;
use Cbox\Dns\Enums\RecordType;

/**
 * A parsed SVCB / HTTPS record (RFC 9460, RFC 9461). Unlike a hex dump, this reads
 * the SvcPriority, the TargetName, and every SvcParam into typed fields: the ALPN
 * set (HTTP/2, HTTP/3 discovery), an alternative port, IPv4/IPv6 address hints, the
 * Encrypted ClientHello config, and the mandatory-key and no-default-alpn markers.
 *
 * `priority == 0` is AliasMode (the record just points at another SVCB target and
 * carries no params); a non-zero priority is ServiceMode.
 *
 * Parsed from the exact wire RDATA (kept on {@see DnsRecord::$raw}), so it is
 * byte-exact and not a re-parse of a lossy presentation string. DoH answers do not
 * carry raw RDATA, so {@see self::fromRecord()} returns null for them.
 */
readonly class Svcb implements RecordData
{
    // RFC 9460 §14.3.2 SvcParamKeys.
    private const int KEY_MANDATORY = 0;

    private const int KEY_ALPN = 1;

    private const int KEY_NO_DEFAULT_ALPN = 2;

    private const int KEY_PORT = 3;

    private const int KEY_IPV4HINT = 4;

    private const int KEY_ECH = 5;

    private const int KEY_IPV6HINT = 6;

    /**
     * @param  list<string>  $alpn  the ALPN protocol ids (e.g. `['h3', 'h2']`)
     * @param  list<string>  $ipv4hint  A-record address hints
     * @param  list<string>  $ipv6hint  AAAA-record address hints
     * @param  list<int>  $mandatory  SvcParamKey ids the client MUST understand
     * @param  ?string  $ech  the Encrypted ClientHello config, base64-encoded
     * @param  array<int, string>  $unknownParams  unrecognised key id => hex value
     */
    public function __construct(
        public int $priority,
        public string $target,
        public array $alpn = [],
        public bool $noDefaultAlpn = false,
        public ?int $port = null,
        public array $ipv4hint = [],
        public array $ipv6hint = [],
        public ?string $ech = null,
        public array $mandatory = [],
        public array $unknownParams = [],
    ) {}

    public function isAlias(): bool
    {
        return $this->priority === 0;
    }

    /**
     * Build from a SVCB/HTTPS {@see DnsRecord} using its raw wire RDATA, or null if
     * the record is the wrong type or carries no raw bytes (e.g. a DoH answer).
     */
    public static function fromRecord(DnsRecord $record): ?self
    {
        if (($record->type !== RecordType::SVCB && $record->type !== RecordType::HTTPS) || $record->raw === null) {
            return null;
        }

        return self::fromRdata($record->raw);
    }

    /**
     * Parse SVCB/HTTPS wire RDATA: 2-byte SvcPriority, an uncompressed TargetName,
     * then a run of `key(2) length(2) value` SvcParams. Returns null on malformed
     * input rather than throwing.
     */
    public static function fromRdata(string $raw): ?self
    {
        $length = strlen($raw);

        if ($length < 3) {
            return null;
        }

        $priority = (ord($raw[0]) << 8) | ord($raw[1]);
        $offset = 2;

        $labels = [];
        while ($offset < $length) {
            $labelLength = ord($raw[$offset]);
            $offset++;

            if ($labelLength === 0) {
                break;
            }

            if (($labelLength & 0xC0) === 0xC0 || $offset + $labelLength > $length) {
                return null; // compression is forbidden here, and must stay in bounds
            }

            $labels[] = substr($raw, $offset, $labelLength);
            $offset += $labelLength;
        }

        $params = [
            'alpn' => [], 'noDefaultAlpn' => false, 'port' => null,
            'ipv4hint' => [], 'ipv6hint' => [], 'ech' => null,
            'mandatory' => [], 'unknown' => [],
        ];

        while ($offset + 4 <= $length) {
            $key = (ord($raw[$offset]) << 8) | ord($raw[$offset + 1]);
            $valueLength = (ord($raw[$offset + 2]) << 8) | ord($raw[$offset + 3]);
            $offset += 4;

            if ($offset + $valueLength > $length) {
                return null; // param runs past the RDATA
            }

            $value = substr($raw, $offset, $valueLength);
            $offset += $valueLength;

            self::applyParam($params, $key, $value);
        }

        return new self(
            $priority,
            $labels === [] ? '.' : implode('.', $labels),
            $params['alpn'],
            $params['noDefaultAlpn'],
            $params['port'],
            $params['ipv4hint'],
            $params['ipv6hint'],
            $params['ech'],
            $params['mandatory'],
            $params['unknown'],
        );
    }

    /**
     * The presentation form (RFC 9460 §2.2), matching what `dig` prints, e.g.
     * `1 . alpn="h3,h2" ipv4hint=104.16.0.1`.
     */
    public function presentation(): string
    {
        $parts = [(string) $this->priority, $this->target];

        if ($this->mandatory !== []) {
            $parts[] = 'mandatory='.implode(',', array_map(self::keyName(...), $this->mandatory));
        }

        if ($this->alpn !== []) {
            $parts[] = 'alpn="'.implode(',', $this->alpn).'"';
        }

        if ($this->noDefaultAlpn) {
            $parts[] = 'no-default-alpn';
        }

        if ($this->port !== null) {
            $parts[] = 'port='.$this->port;
        }

        if ($this->ipv4hint !== []) {
            $parts[] = 'ipv4hint='.implode(',', $this->ipv4hint);
        }

        if ($this->ech !== null) {
            $parts[] = 'ech='.$this->ech;
        }

        if ($this->ipv6hint !== []) {
            $parts[] = 'ipv6hint='.implode(',', $this->ipv6hint);
        }

        foreach ($this->unknownParams as $key => $hex) {
            $parts[] = 'key'.$key.'='.$hex;
        }

        return implode(' ', $parts);
    }

    /**
     * @param  array{alpn: list<string>, noDefaultAlpn: bool, port: int|null, ipv4hint: list<string>, ipv6hint: list<string>, ech: string|null, mandatory: list<int>, unknown: array<int, string>}  $params
     */
    private static function applyParam(array &$params, int $key, string $value): void
    {
        switch ($key) {
            case self::KEY_MANDATORY:
                $params['mandatory'] = self::uint16List($value);
                break;
            case self::KEY_ALPN:
                $params['alpn'] = self::charStringList($value);
                break;
            case self::KEY_NO_DEFAULT_ALPN:
                $params['noDefaultAlpn'] = true;
                break;
            case self::KEY_PORT:
                $params['port'] = strlen($value) >= 2 ? (ord($value[0]) << 8) | ord($value[1]) : null;
                break;
            case self::KEY_IPV4HINT:
                $params['ipv4hint'] = self::addressList($value, 4);
                break;
            case self::KEY_ECH:
                $params['ech'] = base64_encode($value);
                break;
            case self::KEY_IPV6HINT:
                $params['ipv6hint'] = self::addressList($value, 16);
                break;
            default:
                $params['unknown'][$key] = bin2hex($value);
        }
    }

    /**
     * @return list<int>
     */
    private static function uint16List(string $value): array
    {
        $out = [];

        for ($i = 0; $i + 2 <= strlen($value); $i += 2) {
            $out[] = (ord($value[$i]) << 8) | ord($value[$i + 1]);
        }

        return $out;
    }

    /**
     * @return list<string>
     */
    private static function charStringList(string $value): array
    {
        $out = [];
        $offset = 0;
        $length = strlen($value);

        while ($offset < $length) {
            $itemLength = ord($value[$offset]);
            $offset++;

            if ($offset + $itemLength > $length) {
                break; // a length-prefixed id that runs past the value is truncated
            }

            $out[] = substr($value, $offset, $itemLength);
            $offset += $itemLength;
        }

        return $out;
    }

    /**
     * @return list<string>
     */
    private static function addressList(string $value, int $size): array
    {
        $out = [];

        for ($i = 0; $i + $size <= strlen($value); $i += $size) {
            $address = inet_ntop(substr($value, $i, $size));

            if ($address !== false) {
                $out[] = $address;
            }
        }

        return $out;
    }

    private static function keyName(int $key): string
    {
        return match ($key) {
            self::KEY_MANDATORY => 'mandatory',
            self::KEY_ALPN => 'alpn',
            self::KEY_NO_DEFAULT_ALPN => 'no-default-alpn',
            self::KEY_PORT => 'port',
            self::KEY_IPV4HINT => 'ipv4hint',
            self::KEY_ECH => 'ech',
            self::KEY_IPV6HINT => 'ipv6hint',
            default => 'key'.$key,
        };
    }
}
