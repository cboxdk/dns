<?php

declare(strict_types=1);

namespace Cbox\Dns\Protocol;

use Cbox\Dns\Exceptions\MalformedMessage;

/**
 * A forward cursor over a raw DNS message. Handles the fiddly parts of RFC 1035
 * wire format — fixed-width integers and, critically, compressed domain names
 * (0xC0 pointers back into the message) — so the decoder stays readable.
 */
final class Reader
{
    private int $offset = 0;

    public function __construct(private readonly string $message) {}

    public function position(): int
    {
        return $this->offset;
    }

    public function seek(int $offset): void
    {
        $this->offset = $offset;
    }

    public function remaining(): int
    {
        return strlen($this->message) - $this->offset;
    }

    public function uint8(): int
    {
        return ord($this->take(1));
    }

    public function uint16(): int
    {
        $bytes = $this->take(2);

        return (ord($bytes[0]) << 8) | ord($bytes[1]);
    }

    public function uint32(): int
    {
        $bytes = $this->take(4);

        return (ord($bytes[0]) << 24) | (ord($bytes[1]) << 16) | (ord($bytes[2]) << 8) | ord($bytes[3]);
    }

    public function bytes(int $length): string
    {
        return $this->take($length);
    }

    /**
     * Read a (possibly compressed) domain name and return it as a dotted string
     * without the trailing root dot. Pointers are followed against the full
     * message; the cursor is left just past the name in the CURRENT position
     * (never past the pointer target).
     */
    public function name(): string
    {
        $labels = [];
        $jumped = false;
        $savedOffset = 0;
        $guard = 0;

        while (true) {
            if (++$guard > 128) {
                throw MalformedMessage::make('domain name has too many labels or a pointer loop');
            }

            $length = ord($this->at($this->offset));

            // Compression pointer: top two bits set → 14-bit offset follows.
            if (($length & 0xC0) === 0xC0) {
                $pointer = (($length & 0x3F) << 8) | ord($this->at($this->offset + 1));

                if (! $jumped) {
                    $savedOffset = $this->offset + 2;
                    $jumped = true;
                }

                $this->offset = $pointer;

                continue;
            }

            $this->offset++;

            if ($length === 0) {
                break;
            }

            $labels[] = $this->slice($this->offset, $length);
            $this->offset += $length;
        }

        if ($jumped) {
            $this->offset = $savedOffset;
        }

        return implode('.', $labels);
    }

    private function take(int $length): string
    {
        $value = $this->slice($this->offset, $length);
        $this->offset += $length;

        return $value;
    }

    private function slice(int $offset, int $length): string
    {
        if ($offset + $length > strlen($this->message)) {
            throw MalformedMessage::make('read past end of message');
        }

        return substr($this->message, $offset, $length);
    }

    private function at(int $offset): string
    {
        if ($offset >= strlen($this->message)) {
            throw MalformedMessage::make('read past end of message');
        }

        return $this->message[$offset];
    }
}
