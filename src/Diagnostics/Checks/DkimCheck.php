<?php

declare(strict_types=1);

namespace Cbox\Dns\Diagnostics\Checks;

use Cbox\Dns\Diagnostics\Contracts\Check;
use Cbox\Dns\Diagnostics\DiagnosticContext;
use Cbox\Dns\Diagnostics\Finding;
use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Exceptions\DnsException;

/**
 * Checks a DKIM public key at `<selector>._domainkey.<domain>`. DKIM cannot be
 * probed without knowing the selector (there is no way to enumerate selectors over
 * DNS), so this check is constructed with an explicit selector and is NOT part of
 * the default set — the orchestrator only runs it when a host supplies one.
 */
final class DkimCheck implements Check
{
    private const string CATEGORY = 'Email';

    public function __construct(
        private readonly string $selector,
    ) {}

    public function run(DiagnosticContext $ctx): array
    {
        $host = "{$this->selector}._domainkey.{$ctx->domain}";

        try {
            $records = $ctx->resolver->query($host, RecordType::TXT)->values();
        } catch (DnsException) {
            $records = [];
        }

        $dkim = array_values(array_filter(
            $records,
            static fn (string $txt): bool => stripos($txt, 'p=') !== false,
        ));

        if ($dkim === []) {
            return [Finding::warning(
                self::CATEGORY,
                'dkim.presence',
                "No DKIM key at {$host} for selector '{$this->selector}'.",
                ['selector' => $this->selector],
            )];
        }

        $key = $dkim[0];

        if (preg_match('/(^|;)\s*p=\s*($|;)/', $key) === 1) {
            return [Finding::warning(
                self::CATEGORY,
                'dkim.revoked',
                "DKIM key for selector '{$this->selector}' has an empty p= tag — the key is revoked.",
                ['selector' => $this->selector, 'record' => $key],
            )];
        }

        return [Finding::info(
            self::CATEGORY,
            'dkim.presence',
            "DKIM key is published for selector '{$this->selector}'.",
            ['selector' => $this->selector, 'record' => $key],
        )];
    }
}
