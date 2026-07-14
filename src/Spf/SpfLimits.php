<?php

declare(strict_types=1);

namespace Cbox\Dns\Spf;

/**
 * The shared, mutable budget for one SPF evaluation. RFC 7208 §4.6.4 caps the total
 * DNS-querying mechanisms (`include`, `a`, `mx`, `ptr`, `exists`, and `redirect`) at
 * 10 and void lookups at 2 — the guards that make SPF expansion terminate on a
 * hostile or misconfigured policy. (Include loops are broken separately, by the
 * per-branch ancestor path in {@see SpfResolver}.)
 */
class SpfLimits
{
    public const int MAX_LOOKUPS = 10;

    public const int MAX_VOID_LOOKUPS = 2;

    public int $lookups = 0;

    public int $voidLookups = 0;

    /**
     * Charge one DNS-querying mechanism. Returns false once the budget is spent, so
     * the caller stops rather than issuing an 11th lookup (a permerror per RFC 7208).
     */
    public function charge(): bool
    {
        if ($this->lookups >= self::MAX_LOOKUPS) {
            return false;
        }

        $this->lookups++;

        return true;
    }

    public function exceeded(): bool
    {
        return $this->lookups >= self::MAX_LOOKUPS || $this->voidLookups > self::MAX_VOID_LOOKUPS;
    }
}
