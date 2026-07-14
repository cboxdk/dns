<?php

declare(strict_types=1);

namespace Cbox\Dns\Diagnostics\Checks;

use Cbox\Dns\Diagnostics\Contracts\Check;
use Cbox\Dns\Diagnostics\DiagnosticContext;
use Cbox\Dns\Diagnostics\Finding;
use Cbox\Dns\Dnssec\DnssecValidator;
use Cbox\Dns\Dnssec\Enums\ValidationStatus;

/**
 * Wraps the {@see DnssecValidator} chain walk: a `secure` or
 * provably `insecure` (unsigned) zone is an Info note; a `bogus` chain — a broken
 * signature, DS link, or expired RRSIG — is an Error, matching the validator's
 * deny-by-default stance.
 */
class DnssecCheck implements Check
{
    private const string CATEGORY = 'DNSSEC';

    public function run(DiagnosticContext $ctx): array
    {
        $result = $ctx->dnssec->validate($ctx->domain);
        $context = ['status' => $result->status->value, 'reason' => $result->reason];

        return [match ($result->status) {
            ValidationStatus::Secure => Finding::info(
                self::CATEGORY,
                'dnssec.chain',
                "DNSSEC is valid: {$result->reason}.",
                $context,
            ),
            ValidationStatus::Insecure => Finding::info(
                self::CATEGORY,
                'dnssec.chain',
                "The zone is unsigned (no DNSSEC): {$result->reason}.",
                $context,
            ),
            ValidationStatus::Bogus => Finding::error(
                self::CATEGORY,
                'dnssec.chain',
                "DNSSEC validation is bogus: {$result->reason}.",
                $context,
            ),
        }];
    }
}
