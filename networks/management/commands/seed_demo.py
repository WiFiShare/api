"""Fictional networks so a local website has something to render.

Everything this writes is invented. Every SSID carries the word "Demo", the
BSSIDs are in the IANA documentation-style block `00:00:5e:00:53:xx`, and the
venue names are made up, so nothing here can be mistaken for a real network or
a real place.
"""

from __future__ import annotations

from datetime import date, timedelta

from django.core.management.base import BaseCommand, CommandParser
from django.db import transaction

from core import geohash
from networks.models import Network, NetworkBssid, Report
from networks.publish import COMMUNITY_CELL_LENGTH, VERIFIED_DECIMALS

# Two areas: Piazza Maggiore in Bologna (srbj4) and Lisbon's Baixa (eycs5).
SEEDS: list[dict] = [
    {
        "ssid": "Demo Biblioteca Sala Borsa",
        "bssid": "00:00:5e:00:53:01",
        "lat": 44.4938,
        "lon": 11.3426,
        "security": "open",
        "captive_portal": "none",
        "verification": Network.COMMUNITY,
        "reports": {"works": 7, "fails": 1},
    },
    {
        "ssid": "Demo Portico WiFi",
        "bssid": "00:00:5e:00:53:02",
        "lat": 44.4952,
        "lon": 11.3458,
        "security": "owe",
        "captive_portal": "unknown",
        "verification": Network.COMMUNITY,
        "reports": {"works": 3, "fails": 0},
    },
    {
        "ssid": "Demo Parco Libero",
        "bssid": "00:00:5e:00:53:03",
        "lat": 44.4901,
        "lon": 11.3390,
        "security": "open",
        "captive_portal": "detected",
        "verification": Network.COMMUNITY,
        "reports": {"works": 2, "fails": 2},
    },
    {
        "ssid": "Demo Caffe Centrale",
        "bssid": "00:00:5e:00:53:04",
        "lat": 44.49417,
        "lon": 11.34290,
        "security": "shared",
        "captive_portal": "none",
        "verification": Network.OWNER_VERIFIED,
        "venue": {"name": "Demo Caffè Centrale (fictional)", "kind": "cafe"},
        "credential": {
            "type": "wpa2-psk",
            "secret": "demo-not-a-real-password",
            "note": "Ask at the bar",
        },
        "extra_bssids": ["00:00:5e:00:53:05"],
        "reports": {"works": 11, "fails": 0},
    },
    {
        "ssid": "Demo Praca WiFi",
        "bssid": "00:00:5e:00:53:06",
        "lat": 38.7100,
        "lon": -9.1400,
        "security": "open",
        "captive_portal": "unknown",
        "verification": Network.COMMUNITY,
        "reports": {"works": 4, "fails": 1},
    },
    {
        "ssid": "Demo Livraria Aberta",
        "bssid": "00:00:5e:00:53:07",
        "lat": 38.7123,
        "lon": -9.1365,
        "security": "open",
        "captive_portal": "none",
        "verification": Network.COMMUNITY,
        "reports": {"works": 5, "fails": 0},
    },
]


class Command(BaseCommand):
    help = "Create a handful of clearly fictional published networks for local work."

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument(
            "--clear", action="store_true", help="Delete the demo networks instead of adding them."
        )

    @transaction.atomic
    def handle(self, *args: object, **options: object) -> None:
        demo_bssids = [seed["bssid"] for seed in SEEDS] + [
            bssid for seed in SEEDS for bssid in seed.get("extra_bssids", [])
        ]

        if options["clear"]:
            deleted = Network.objects.filter(bssids__bssid__in=demo_bssids).distinct().delete()
            self.stdout.write(f"removed demo networks ({deleted[0]} rows)")
            return

        today = date.today()
        for seed in SEEDS:
            network = self._upsert(seed, today)
            self.stdout.write(f"{network.public_id}  {network.ssid}  {network.cell}")

        self.stdout.write(f"seeded {len(SEEDS)} fictional networks")

    def _upsert(self, seed: dict, today: date) -> Network:
        link = NetworkBssid.objects.filter(bssid=seed["bssid"]).select_related("network").first()
        network = link.network if link else Network()

        verified = seed["verification"] == Network.OWNER_VERIFIED
        cell = geohash.encode(seed["lat"], seed["lon"], COMMUNITY_CELL_LENGTH)
        if verified:
            lat, lon = round(seed["lat"], VERIFIED_DECIMALS), round(seed["lon"], VERIFIED_DECIMALS)
        else:
            lat, lon = geohash.centre(cell)

        network.ssid = seed["ssid"]
        network.security = seed["security"]
        network.captive_portal = seed["captive_portal"]
        network.verification = seed["verification"]
        network.lat, network.lon, network.cell = lat, lon, cell
        network.first_seen = today - timedelta(days=40)
        network.last_seen = today - timedelta(days=1)
        network.observation_count = 12
        network.is_published = True
        network.unpublished_reason = ""
        if verified:
            network.venue_name = seed["venue"]["name"]
            network.venue_kind = seed["venue"].get("kind", "")
            network.publish_credential = True
            network.credential_type = seed["credential"]["type"]
            network.credential_secret = seed["credential"]["secret"]
            network.credential_note = seed["credential"].get("note", "")
        network.save()

        for bssid in [seed["bssid"], *seed.get("extra_bssids", [])]:
            NetworkBssid.objects.update_or_create(bssid=bssid, defaults={"network": network})

        network.reports.all().delete()
        Report.objects.bulk_create(
            Report(network=network, kind=kind)
            for kind, count in seed["reports"].items()
            for _ in range(count)
        )
        return network
