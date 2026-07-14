<?php

declare(strict_types=1);

use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Protocol\Encoder;

it('appends an EDNS0 OPT record with the DO bit when dnssec is requested', function (): void {
    $query = (new Encoder)->query('example.com', RecordType::A, recursion: true, id: 0x1234, dnssec: true);

    // ARCOUNT (last 2 header octets) must be 1.
    expect(unpack('n', substr($query, 10, 2))[1])->toBe(1);

    // The OPT RR is the final 11 octets: root name, TYPE, CLASS, TTL, RDLEN.
    $opt = substr($query, -11);

    expect($opt[0])->toBe("\x00")                              // root owner name
        ->and(unpack('n', substr($opt, 1, 2))[1])->toBe(41)   // TYPE = OPT
        ->and(unpack('n', substr($opt, 3, 2))[1])->toBe(4096) // UDP payload size
        ->and(unpack('N', substr($opt, 5, 4))[1])->toBe(0x00008000) // DO bit in TTL
        ->and(unpack('n', substr($opt, 9, 2))[1])->toBe(0);   // RDLENGTH = 0
});

it('omits the OPT record and keeps ARCOUNT zero without dnssec', function (): void {
    $query = (new Encoder)->query('example.com', RecordType::A, recursion: true, id: 0x1234);

    expect(unpack('n', substr($query, 10, 2))[1])->toBe(0)
        // header (12) + qname (13) + qtype/qclass (4) = 29 octets, no OPT.
        ->and(strlen($query))->toBe(29);
});
