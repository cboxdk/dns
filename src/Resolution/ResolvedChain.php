<?php

declare(strict_types=1);

namespace Cbox\Dns\Resolution;

use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\ValueObjects\DnsRecord;

/**
 * The result of following a name's CNAME chain to its answer: the ordered CNAME
 * hops that were traversed (traceability), the canonical name they resolved to, and
 * the final records of the requested type. `completed` is false — with a
 * `stoppedReason` — when the chain looped, dead-ended, or errored.
 */
readonly class ResolvedChain
{
    /**
     * @param  list<CnameHop>  $chain  the CNAME hops followed, in order
     * @param  list<DnsRecord>  $answer  the final records of the requested type
     */
    public function __construct(
        public string $host,
        public RecordType $type,
        public array $chain,
        public array $answer,
        public bool $completed,
        public ?string $stoppedReason = null,
    ) {}

    /**
     * The canonical name the chain ended at (the last CNAME target, or the original
     * host if there were no CNAMEs).
     */
    public function canonicalName(): string
    {
        return $this->chain === [] ? $this->host : $this->chain[array_key_last($this->chain)]->to;
    }

    /**
     * Every name traversed, from the queried host through each CNAME target.
     *
     * @return list<string>
     */
    public function aliases(): array
    {
        $names = [$this->host];

        foreach ($this->chain as $hop) {
            $names[] = $hop->to;
        }

        return $names;
    }

    /**
     * The final answer values (e.g. the IPs an A chain resolved to).
     *
     * @return list<string>
     */
    public function values(): array
    {
        return array_map(static fn (DnsRecord $r): string => $r->value, $this->answer);
    }
}
