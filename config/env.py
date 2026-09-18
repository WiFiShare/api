"""Reading configuration out of the environment.

Small on purpose: a DATABASE_URL parser and three typed getters are cheaper
than a dependency, and they make the defaults visible in one place.
"""

from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import unquote, urlparse

TRUE_VALUES = {"1", "true", "yes", "on"}


def get_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in TRUE_VALUES


def get_list(name: str, default: list[str] | None = None) -> list[str]:
    raw = os.environ.get(name)
    if not raw:
        return list(default or [])
    return [item.strip() for item in raw.split(",") if item.strip()]


def get_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    return int(raw)


ENGINES = {
    "postgres": "django.db.backends.postgresql",
    "postgresql": "django.db.backends.postgresql",
    "psql": "django.db.backends.postgresql",
    "sqlite": "django.db.backends.sqlite3",
    "sqlite3": "django.db.backends.sqlite3",
}


def database_from_url(url: str, base_dir: Path) -> dict[str, object]:
    """Turn a DATABASE_URL into a Django DATABASES entry.

    Supports `sqlite:///relative/path.sqlite3`, `sqlite:////absolute/path` and
    `postgres://user:password@host:port/name`, which is every form this
    project's docker-compose and local setup need.
    """
    parsed = urlparse(url)
    scheme = parsed.scheme.split("+", 1)[0].lower()
    try:
        engine = ENGINES[scheme]
    except KeyError:
        raise ValueError(f"unsupported DATABASE_URL scheme: {parsed.scheme!r}") from None

    if engine.endswith("sqlite3"):
        path = unquote(parsed.path or "")
        if url.endswith(":memory:") or path in ("", "/", "/:memory:"):
            name: object = ":memory:"
        elif path.startswith("//"):
            name = path[1:]  # sqlite:////abs/path -> /abs/path
        else:
            name = str(base_dir / path.lstrip("/"))
        return {"ENGINE": engine, "NAME": name}

    return {
        "ENGINE": engine,
        "NAME": unquote(parsed.path or "").lstrip("/"),
        "USER": unquote(parsed.username or ""),
        "PASSWORD": unquote(parsed.password or ""),
        "HOST": parsed.hostname or "",
        "PORT": str(parsed.port or ""),
        "CONN_MAX_AGE": 60,
    }
