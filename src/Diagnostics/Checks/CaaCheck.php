<?php

declare(strict_types=1);

namespace Cbox\Dns\Diagnostics\Checks;

use Cbox\Dns\Diagnostics\Contracts\Check;
use Cbox\Dns\Diagnostics\DiagnosticContext;
use Cbox\Dns\Diagnostics\Finding;
use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Exceptions\DnsException;

/**
 * Reports whether the apex publishes a CAA record. CAA restricts which CAs may
 * issue certificates for the domain; its absence is not a fault (any CA may issue),
 * so both outcomes are Info — presence is simply worth surfacing.
 */
class CaaCheck implements Check
{
    private const string CATEGORY = 'CAA';

    public function run(DiagnosticContext $ctx): array
    {
        try {
            $values = $ctx->resolver->query($ctx->domain, RecordType::CAA)->values();
        } catch (DnsException) {
            $values = [];
        }

        if ($values === []) {
            return [Finding::info(
                self::CATEGORY,
                'caa.presence',
                'No CAA record at the apex — any certificate authority may issue for this domain.',
            )];
        }

        return [Finding::info(
            self::CATEGORY,
            'caa.presence',
            'CAA is present, restricting which certificate authorities may issue.',
            ['records' => $values],
        )];
    }
}
