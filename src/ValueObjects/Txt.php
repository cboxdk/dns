<?php

declare(strict_types=1);

namespace Cbox\Dns\ValueObjects;

use Cbox\Dns\Contracts\RecordData;

/**
 * A parsed TXT record — the concatenated text of its character-strings. Many TXT
 * records carry a known policy grammar; {@see self::spf()}, {@see self::dkim()}, and
 * {@see self::dmarc()} parse those into typed objects when the text matches.
 */
readonly class Txt implements RecordData
{
    public function __construct(
        public string $text,
    ) {}

    /**
     * The SPF policy if this TXT record is one (`v=spf1 …`), else null.
     */
    public function spf(): ?SpfPolicy
    {
        return SpfPolicy::parse($this->text);
    }

    /**
     * The DKIM key if this TXT record is one (a `p=` public key), else null.
     */
    public function dkim(): ?DkimKey
    {
        return DkimKey::parse($this->text);
    }

    /**
     * The DMARC policy if this TXT record is one (`v=DMARC1 …`), else null.
     */
    public function dmarc(): ?DmarcPolicy
    {
        return DmarcPolicy::parse($this->text);
    }

    public function presentation(): string
    {
        return $this->text;
    }
}
