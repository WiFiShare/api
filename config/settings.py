"""Settings for the WiFiShare API.

Everything that differs between a laptop and a deployment comes from the
environment, with defaults that are safe to run with but not to trust:
DEBUG is off, ALLOWED_HOSTS is localhost, and the database is a local SQLite
file. See .env.example.
"""

from __future__ import annotations

import os
from pathlib import Path

from config.env import database_from_url, get_bool, get_int, get_list

BASE_DIR = Path(__file__).resolve().parent.parent

# --- Security -------------------------------------------------------------

# A stand-in so a checkout runs with no setup at all. The check below refuses
# to start with it once ALLOWED_HOSTS names anything but a local host.
DEV_SECRET_KEY = "dev-only-not-a-secret-set-SECRET_KEY-in-the-environment"
SECRET_KEY = os.environ.get("SECRET_KEY", DEV_SECRET_KEY)

DEBUG = get_bool("DEBUG", False)

ALLOWED_HOSTS = get_list("ALLOWED_HOSTS", ["localhost", "127.0.0.1", "[::1]"])

# The development key is tolerated only while the service answers to local
# names. Any deployment sets ALLOWED_HOSTS to a real host, and that is the
# moment this refuses to start without a real SECRET_KEY.
LOCAL_HOSTS = {"localhost", "127.0.0.1", "[::1]", "::1", "testserver"}
if SECRET_KEY == DEV_SECRET_KEY and not set(ALLOWED_HOSTS).issubset(LOCAL_HOSTS):
    raise RuntimeError(
        "SECRET_KEY must be set in the environment when ALLOWED_HOSTS names a real host"
    )

SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "no-referrer"
X_FRAME_OPTIONS = "DENY"
SESSION_COOKIE_SECURE = not DEBUG
CSRF_COOKIE_SECURE = not DEBUG
CSRF_TRUSTED_ORIGINS = get_list("CSRF_TRUSTED_ORIGINS")

# Turned on together: redirecting to HTTPS and promising HSTS only make sense
# once something in front of us actually terminates TLS.
BEHIND_TLS_PROXY = get_bool("BEHIND_TLS_PROXY")
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https") if BEHIND_TLS_PROXY else None
SECURE_SSL_REDIRECT = BEHIND_TLS_PROXY
SECURE_HSTS_SECONDS = 31_536_000 if BEHIND_TLS_PROXY else 0
SECURE_HSTS_INCLUDE_SUBDOMAINS = BEHIND_TLS_PROXY
# Preload is a commitment that is hard to undo; opt in deliberately, not here.
SECURE_HSTS_PRELOAD = False

# --- Application ----------------------------------------------------------

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "ingest",
    "networks",
    "dump",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "config.urls"
WSGI_APPLICATION = "config.wsgi.application"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

DATABASES = {
    "default": database_from_url(
        os.environ.get("DATABASE_URL", "sqlite:///wifishare.sqlite3"), BASE_DIR
    )
}

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LANGUAGE_CODE = "en-gb"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"

# --- WiFiShare ------------------------------------------------------------

#: Where the spec repo is checked out. Used by the acceptance tests, which read
#: the normative fixtures straight from it rather than from a copy.
SPEC_DIR = Path(os.environ.get("WIFISHARE_SPEC_DIR", BASE_DIR.parent / "spec"))

#: Server-held pepper for the opt-out HMACs (P5). Without it the opt-out list
#: would have to hold BSSIDs in the clear.
OPTOUT_PEPPER = os.environ.get("OPTOUT_PEPPER", SECRET_KEY).encode("utf-8")

#: Requests per rolling window, per rate-limit bucket, per endpoint group.
RATE_LIMITS: dict[str, tuple[int, int]] = {  # scope -> (limit, window seconds)
    "batches": (get_int("RATE_LIMIT_BATCHES", 60), 3600),
    "reports": (get_int("RATE_LIMIT_REPORTS", 30), 3600),
    "optout": (get_int("RATE_LIMIT_OPTOUT", 10), 3600),
    "claims": (get_int("RATE_LIMIT_CLAIMS", 10), 3600),
}

#: How long a rotated ingest key keeps decrypting envelopes already in flight.
KEY_GRACE_DAYS = get_int("KEY_GRACE_DAYS", 30)

#: Set when the service sits behind a proxy you control, so the rate-limit
#: bucket is derived from the real client address rather than the proxy's. The
#: address is hashed immediately either way and never stored or logged.
TRUST_X_FORWARDED_FOR = get_bool("TRUST_X_FORWARDED_FOR", False)

AREA_CACHE_SECONDS = get_int("AREA_CACHE_SECONDS", 3600)

# --- Logging --------------------------------------------------------------

# Deliberately narrow. `django.server` is the only stock logger that writes a
# client IP address to the log, so it is sent to a null handler and not allowed
# to propagate. Nothing else in this project logs anything derived from an
# address. tests/test_no_ip_logging.py pins this.
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "plain": {"format": "%(asctime)s %(levelname)s %(name)s %(message)s"},
    },
    "handlers": {
        "console": {"class": "logging.StreamHandler", "formatter": "plain"},
        "null": {"class": "logging.NullHandler"},
    },
    "loggers": {
        "django": {"handlers": ["console"], "level": os.environ.get("LOG_LEVEL", "INFO")},
        # The runserver access log. It prints the client address; we do not
        # want that in any log file, in development either.
        "django.server": {"handlers": ["null"], "level": "CRITICAL", "propagate": False},
        "wifishare": {"handlers": ["console"], "level": os.environ.get("LOG_LEVEL", "INFO")},
    },
}
