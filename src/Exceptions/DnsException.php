<?php

declare(strict_types=1);

namespace Cbox\Dns\Exceptions;

use RuntimeException;

/**
 * Base for every failure this package raises, so callers can catch one type.
 */
abstract class DnsException extends RuntimeException {}
