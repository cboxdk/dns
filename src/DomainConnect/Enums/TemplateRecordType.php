<?php

declare(strict_types=1);

namespace Cbox\Dns\DomainConnect\Enums;

/**
 * The record types a Domain Connect template may contain. SPFM and APEXCNAME
 * are Domain Connect pseudo-types: SPFM merges SPF rules into one record,
 * APEXCNAME is a CNAME-like record at the zone apex.
 */
enum TemplateRecordType: string
{
    case A = 'A';
    case AAAA = 'AAAA';
    case CNAME = 'CNAME';
    case NS = 'NS';
    case TXT = 'TXT';
    case MX = 'MX';
    case SRV = 'SRV';
    case SPFM = 'SPFM';
    case APEXCNAME = 'APEXCNAME';
}
