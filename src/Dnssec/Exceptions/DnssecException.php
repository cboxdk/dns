<?php

declare(strict_types=1);

namespace Cbox\Dns\Dnssec\Exceptions;

use Cbox\Dns\Exceptions\DnsException;

/**
 * Base for every failure raised inside the DNSSEC module, so callers can catch
 * one type. Extends the package-wide {@see DnsException}.
 */
abstract class DnssecException extends DnsException {}
