"""Logging must never carry a client address.

`django.server` is the only stock logger that prints one. This pins the
settings that silence it, and then actually exercises the request path with
logging captured, so a future handler that reintroduces an address fails here.
"""

from __future__ import annotations

import json
import logging

from django.conf import settings
from django.test import TestCase

from tests.helpers import batch, make_key, seal_envelope

ADDRESS = "203.0.113.47"


class LoggingConfigTest(TestCase):
    def test_django_server_logger_is_silenced_and_does_not_propagate(self) -> None:
        configured = settings.LOGGING["loggers"]["django.server"]
        self.assertEqual(configured["handlers"], ["null"])
        self.assertFalse(configured["propagate"])

        logger = logging.getLogger("django.server")
        self.assertFalse(logger.propagate)
        self.assertTrue(all(isinstance(h, logging.NullHandler) for h in logger.handlers))

    def test_no_formatter_interpolates_a_request(self) -> None:
        for name, formatter in settings.LOGGING["formatters"].items():
            with self.subTest(formatter=name):
                self.assertNotIn("%(request)", formatter["format"])


class _Capture(logging.Handler):
    """Collects every record reaching the root logger, formatted."""

    def __init__(self) -> None:
        super().__init__(level=logging.NOTSET)
        self.lines: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.lines.append(f"{record.name} {record.getMessage()} {record.args!r}")


class RequestLoggingTest(TestCase):
    def capture(self):
        handler = _Capture()
        root = logging.getLogger()
        previous_level = root.level
        root.addHandler(handler)
        root.setLevel(logging.NOTSET)
        self.addCleanup(root.setLevel, previous_level)
        self.addCleanup(root.removeHandler, handler)
        return handler

    def test_a_rejected_request_does_not_log_the_address(self) -> None:
        handler = self.capture()

        response = self.client.post(
            "/v1/batches", data="not json", content_type="application/json", REMOTE_ADDR=ADDRESS
        )

        self.assertEqual(response.status_code, 400)
        self.assertTrue(handler.lines, "expected Django to log the rejection at all")
        self.assertFalse(any(ADDRESS in line for line in handler.lines), handler.lines)

    def test_an_accepted_batch_does_not_log_the_address(self) -> None:
        key = make_key()
        handler = self.capture()

        response = self.client.post(
            "/v1/batches",
            data=json.dumps(seal_envelope(key, batch())),
            content_type="application/json",
            REMOTE_ADDR=ADDRESS,
        )

        self.assertEqual(response.status_code, 202)
        self.assertFalse(any(ADDRESS in line for line in handler.lines), handler.lines)

    def test_a_rate_limited_request_does_not_log_the_address(self) -> None:
        from django.test import override_settings

        key = make_key()
        handler = self.capture()
        limits = {scope: (1, 3600) for scope in ("batches", "reports", "optout", "claims")}
        with override_settings(RATE_LIMITS=limits):
            for _ in range(2):
                self.client.post(
                    "/v1/batches",
                    data=json.dumps(seal_envelope(key, batch())),
                    content_type="application/json",
                    REMOTE_ADDR=ADDRESS,
                )

        self.assertTrue(handler.lines)
        self.assertFalse(any(ADDRESS in line for line in handler.lines), handler.lines)
