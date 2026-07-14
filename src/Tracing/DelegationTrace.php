<?php

declare(strict_types=1);

namespace Cbox\Dns\Tracing;

use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\ValueObjects\DnsRecord;

/**
 * The result of tracing a name's delegation from the root down: the ordered hops
 * (each zone cut and the server that answered it), the final answer records if the
 * chain resolved, and a note on why it stopped.
 */
readonly class DelegationTrace
{
    /**
     * @param  list<DelegationHop>  $hops
     * @param  list<DnsRecord>  $answer  the final answer records, if reached
     */
    public function __construct(
        public string $name,
        public RecordType $type,
        public array $hops,
        public array $answer,
        public bool $completed,
        public ?string $stoppedReason = null,
    ) {}

    /**
     * The zones traversed, outermost first — e.g. `['.', 'com', 'example.com']`.
     *
     * @return list<string>
     */
    public function path(): array
    {
        return array_map(static fn (DelegationHop $h): string => $h->zone, $this->hops);
    }

    /**
     * The final authoritative nameservers reached (the last hop's referral set), or
     * an empty list if the trace never reached a delegation.
     *
     * @return list<string>
     */
    public function authoritativeNameservers(): array
    {
        for ($i = count($this->hops) - 1; $i >= 0; $i--) {
            if ($this->hops[$i]->referralNameservers !== []) {
                return $this->hops[$i]->referralNameservers;
            }
        }

        return [];
    }
}
