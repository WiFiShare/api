"""Geohash encode/decode, as described in spec/docs/geohash.md.

Only what the project needs: encode a position to a prefix, and recover the
centre of a cell. Implemented here rather than pulled in as a dependency
because the exact rounding behaviour is part of the privacy contract (a
community network's published position *is* its cell centre) and we want that
pinned by our own tests.
"""

from __future__ import annotations

# The standard geohash alphabet: base32 without a, i, l and o.
ALPHABET = "0123456789bcdefghjkmnpqrstuvwxyz"
_DECODE = {c: i for i, c in enumerate(ALPHABET)}


def encode(lat: float, lon: float, precision: int) -> str:
    """Encode a WGS84 position as a geohash of `precision` characters."""
    if precision < 1:
        raise ValueError("precision must be at least 1")

    lat_lo, lat_hi = -90.0, 90.0
    lon_lo, lon_hi = -180.0, 180.0
    out: list[str] = []
    bits = 0
    bit_count = 0
    even = True  # even bits split longitude

    while len(out) < precision:
        if even:
            mid = (lon_lo + lon_hi) / 2
            if lon > mid:
                bits = (bits << 1) | 1
                lon_lo = mid
            else:
                bits <<= 1
                lon_hi = mid
        else:
            mid = (lat_lo + lat_hi) / 2
            if lat > mid:
                bits = (bits << 1) | 1
                lat_lo = mid
            else:
                bits <<= 1
                lat_hi = mid
        even = not even
        bit_count += 1
        if bit_count == 5:
            out.append(ALPHABET[bits])
            bits = 0
            bit_count = 0

    return "".join(out)


def bounds(cell: str) -> tuple[float, float, float, float]:
    """Return (lat_lo, lat_hi, lon_lo, lon_hi) for a geohash cell."""
    lat_lo, lat_hi = -90.0, 90.0
    lon_lo, lon_hi = -180.0, 180.0
    even = True

    for char in cell:
        try:
            value = _DECODE[char]
        except KeyError:
            raise ValueError(f"not a geohash character: {char!r}") from None
        for shift in (4, 3, 2, 1, 0):
            bit = (value >> shift) & 1
            if even:
                mid = (lon_lo + lon_hi) / 2
                if bit:
                    lon_lo = mid
                else:
                    lon_hi = mid
            else:
                mid = (lat_lo + lat_hi) / 2
                if bit:
                    lat_lo = mid
                else:
                    lat_hi = mid
            even = not even

    return lat_lo, lat_hi, lon_lo, lon_hi


def centre(cell: str) -> tuple[float, float]:
    """Return the (lat, lon) centre of a geohash cell."""
    lat_lo, lat_hi, lon_lo, lon_hi = bounds(cell)
    return (lat_lo + lat_hi) / 2, (lon_lo + lon_hi) / 2


def neighbours(cell: str) -> list[str]:
    """The eight cells around `cell`, for clients that search near an edge."""
    lat_lo, lat_hi, lon_lo, lon_hi = bounds(cell)
    lat_step = lat_hi - lat_lo
    lon_step = lon_hi - lon_lo
    lat_c, lon_c = centre(cell)
    out = []
    for dlat in (-1, 0, 1):
        for dlon in (-1, 0, 1):
            if dlat == 0 and dlon == 0:
                continue
            lat = max(-90.0, min(90.0, lat_c + dlat * lat_step))
            lon = lon_c + dlon * lon_step
            if lon > 180:
                lon -= 360
            elif lon < -180:
                lon += 360
            out.append(encode(lat, lon, len(cell)))
    return out
