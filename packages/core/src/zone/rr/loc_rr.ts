// LOC Resource Record (RFC 1876)
//
// Wire format (RFC 1876 §2):
//   VERSION(1) + SIZE(1) + HORIZ_PRE(1) + VERT_PRE(1)
//   + LATITUDE(4) + LONGITUDE(4) + ALTITUDE(4)
//   Total: 16 octets (fixed)
//
// Latitude/Longitude: uint32 in thousandths of arc-second.
//   2^31 (2147483648) = equator/prime meridian. North/East > 2^31.
//
// Altitude: uint32 in centimeters, offset by 10,000,000 (= 100,000m below WGS84).
//
// Size/precision: encoded as XeY in one byte (high nibble=mantissa, low nibble=exponent).
//   Represents mantissa * 10^exponent centimeters.
//
// Presentation format (RFC 1876 §3):
//   d1 [m1 [s1.frac]] {N|S} d2 [m2 [s2.frac]] {E|W} alt["m"] [siz["m"] [hp["m"] [vp["m"]]]]

import { WireBuilder } from '../../wire/dns_wire_util';
import { StringToRRType } from '../../types/dns_type_table';
import { ResourceRecord, ResourceRecordHandler, register_rr_handler } from '../dns_zone';
import { DNSZonePresentationFormatError } from '../../lib/dns_exception';

const EQUATOR = 2147483648;  // 2^31
const ALT_OFFSET = 10000000; // 100,000m in centimeters

// RFC 1876 §2: Encode size/precision value as one byte (mantissa * 10^exponent centimeters)
function encodeSizePrecision(meters: number): number {
    let cm = Math.round(meters * 100);
    if (cm <= 0) return 0x00;  // 0e0 = 0

    let exp = 0;
    while (cm >= 10 && exp < 9) {
        cm = Math.round(cm / 10);
        exp++;
    }
    if (cm > 9) cm = 9;
    return (cm << 4) | exp;
}

// Parse a coordinate string: "d [m [s.frac]] {N|S|E|W}"
// Returns [value_in_thousandths_of_arc_second, tokens_consumed, is_positive]
function parseCoordinate(tokens: string[], startIdx: number, posChar: string, negChar: string): [number, number] {
    let idx = startIdx;
    let degrees = 0, minutes = 0, seconds = 0;

    degrees = parseInt(tokens[idx++]);

    // Check if next token is a direction indicator
    if (idx < tokens.length && (tokens[idx] === posChar || tokens[idx] === negChar)) {
        // Only degrees provided
    } else if (idx < tokens.length && !isNaN(parseInt(tokens[idx]))) {
        minutes = parseInt(tokens[idx++]);
        if (idx < tokens.length && (tokens[idx] === posChar || tokens[idx] === negChar)) {
            // degrees + minutes
        } else if (idx < tokens.length && !isNaN(parseFloat(tokens[idx]))) {
            seconds = parseFloat(tokens[idx++]);
        }
    }

    // Direction
    if (idx >= tokens.length) {
        throw new DNSZonePresentationFormatError("LOC: missing direction indicator");
    }
    const dir = tokens[idx++];
    const positive = dir === posChar;
    if (!positive && dir !== negChar) {
        throw new DNSZonePresentationFormatError("LOC: expected " + posChar + " or " + negChar + ", got " + dir);
    }

    // Convert to thousandths of arc-second
    const totalMilliseconds = Math.round(
        ((degrees * 3600) + (minutes * 60) + seconds) * 1000
    );

    // Encode as offset from equator/prime meridian
    const wireValue = positive ? EQUATOR + totalMilliseconds : EQUATOR - totalMilliseconds;
    return [wireValue, idx - startIdx];
}

// Parse altitude: number optionally followed by "m", in meters
function parseAltitude(s: string): number {
    const cleaned = s.endsWith('m') ? s.slice(0, -1) : s;
    return parseFloat(cleaned);
}

// Parse size/precision: number optionally followed by "m", in meters
function parseSizePrec(s: string): number {
    const cleaned = s.endsWith('m') ? s.slice(0, -1) : s;
    return parseFloat(cleaned);
}

export class DNSRR_LOC extends ResourceRecordHandler {
    readonly version: number;
    readonly size: number;        // encoded byte
    readonly horiz_pre: number;   // encoded byte
    readonly vert_pre: number;    // encoded byte
    readonly latitude: number;    // uint32
    readonly longitude: number;   // uint32
    readonly altitude: number;    // uint32

    constructor(rr: ResourceRecord | null, value: string) {
        super(rr);
        // RFC 1876 §3: Parse presentation format
        const tokens = value.trim().split(/\s+/);
        let idx = 0;

        // Parse latitude: d [m [s]] {N|S}
        const [lat, latConsumed] = parseCoordinate(tokens, idx, 'N', 'S');
        idx += latConsumed;

        // Parse longitude: d [m [s]] {E|W}
        const [lon, lonConsumed] = parseCoordinate(tokens, idx, 'E', 'W');
        idx += lonConsumed;

        // Parse altitude (required)
        if (idx >= tokens.length) {
            throw new DNSZonePresentationFormatError("LOC: missing altitude");
        }
        const altMeters = parseAltitude(tokens[idx++]);
        this.altitude = Math.round(altMeters * 100) + ALT_OFFSET;

        // RFC 1876 §3: Optional fields with defaults
        // Size default: 1m, horiz_pre default: 10000m, vert_pre default: 10m
        const sizeMeters = idx < tokens.length ? parseSizePrec(tokens[idx++]) : 1;
        const hpMeters = idx < tokens.length ? parseSizePrec(tokens[idx++]) : 10000;
        const vpMeters = idx < tokens.length ? parseSizePrec(tokens[idx++]) : 10;

        this.version = 0;
        this.size = encodeSizePrecision(sizeMeters);
        this.horiz_pre = encodeSizePrecision(hpMeters);
        this.vert_pre = encodeSizePrecision(vpMeters);
        this.latitude = lat;
        this.longitude = lon;
    }

    // RFC 1876 §2: Fixed 16-byte RDATA
    get_wire_body(builder: WireBuilder): void {
        builder.append_uint16(16);  // rdlen
        builder.append_uint8(this.version);
        builder.append_uint8(this.size);
        builder.append_uint8(this.horiz_pre);
        builder.append_uint8(this.vert_pre);
        builder.append_uint32(this.latitude);
        builder.append_uint32(this.longitude);
        builder.append_uint32(this.altitude);
    }

    clone(): DNSRR_LOC {
        return new DNSRR_LOC(this._rr, this.value);
    }
}

register_rr_handler(StringToRRType('LOC'), (rr, value) => new DNSRR_LOC(rr, value));
