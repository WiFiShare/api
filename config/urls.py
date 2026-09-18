"""URL map for version 1 of the API, as defined in spec/openapi.yaml."""

from django.contrib import admin
from django.urls import path

from ingest import views as ingest_views
from networks import views as network_views

urlpatterns = [
    path("v1/keys", ingest_views.keys, name="keys"),
    path("v1/batches", ingest_views.batches, name="batches"),
    path("v1/areas/<str:geohash5>", network_views.area, name="area"),
    path("v1/networks/<str:network_id>/reports", network_views.reports, name="reports"),
    path("v1/optout", network_views.optout, name="optout"),
    path("v1/claims", network_views.claims, name="claims"),
    path("v1/claims/<str:claim_id>/verify", network_views.verify_claim, name="verify-claim"),
    path("admin/", admin.site.urls),
]
