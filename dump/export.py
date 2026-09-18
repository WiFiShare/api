"""Writing the public dump.

The layout is fixed by spec/docs/geohash.md and the data repository's README:

    areas/<gh2>/<gh3>/<gh5>.geojson

where the three segments are prefixes of one geohash, not three values. Each
file is an area document identical to what `GET /v1/areas/{gh5}` returns, and
`index.json`, defined by spec/schemas/index.schema.json, lists the areas that
exist so a consumer need not probe for files. The index holds no paths: an
area's path follows from its geohash by the rule above.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import date
from pathlib import Path

from networks import publish
from networks.models import Network

INDEX_SCHEMA = "wifishare.index/1"

#: The shape the data repository documents for an empty dump.
EMPTY_INDEX = {
    "schema": INDEX_SCHEMA,
    "generated": None,
    "network_count": 0,
    "area_count": 0,
    "areas": {},
}


@dataclass
class ExportResult:
    out_dir: Path
    area_count: int
    network_count: int
    files: list[Path]


def relative_area_path(cell5: str) -> str:
    """Where an area's file lives, relative to the root of the dump."""
    return f"areas/{cell5[:2]}/{cell5[:3]}/{cell5}.geojson"


def area_path(out_dir: Path, cell5: str) -> Path:
    return out_dir / relative_area_path(cell5)


def _write_json(path: Path, document: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=1, sort_keys=True) + "\n", encoding="utf-8")


def export(out_dir: Path, *, generated: date | None = None) -> ExportResult:
    """Write every published area plus index.json under `out_dir`."""
    generated = generated or date.today()
    out_dir = Path(out_dir)

    by_cell: dict[str, list[Network]] = {}
    for network in (
        Network.objects.filter(is_published=True)
        .exclude(cell="")
        .prefetch_related("bssids", "reports")
        .order_by("public_id")
    ):
        by_cell.setdefault(network.cell[: publish.AREA_CELL_LENGTH], []).append(network)

    files: list[Path] = []
    areas: dict[str, dict[str, object]] = {}
    total = 0
    for cell5 in sorted(by_cell):
        networks = by_cell[cell5]
        path = area_path(out_dir, cell5)
        _write_json(path, publish.area_document(cell5, networks, generated))
        files.append(path)
        areas[cell5] = {"network_count": len(networks), "updated": generated.isoformat()}
        total += len(networks)

    index = {
        "schema": INDEX_SCHEMA,
        "generated": generated.isoformat() if areas else None,
        "network_count": total,
        "area_count": len(areas),
        "areas": areas,
    }
    _write_json(out_dir / "index.json", index)

    return ExportResult(out_dir=out_dir, area_count=len(areas), network_count=total, files=files)
