# WiFiShare API.
#
# Build:  docker build -t wifishare-api .
# Run:    docker compose up  (see docker-compose.yml)
#
# The image carries no secrets: SECRET_KEY, OPTOUT_PEPPER and DATABASE_URL all
# come from the environment at run time.

FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    PATH="/opt/venv/bin:$PATH" \
    DJANGO_SETTINGS_MODULE=config.settings

COPY --from=ghcr.io/astral-sh/uv:0.11 /uv /usr/local/bin/uv

WORKDIR /srv/app

# Dependencies first, so a code change does not re-resolve them.
COPY pyproject.toml uv.lock ./
RUN uv sync --locked --no-dev --extra postgres --extra server

COPY . .

RUN python manage.py collectstatic --noinput \
    && useradd --system --uid 10001 --home /srv/app wifishare \
    && chown -R wifishare:wifishare /srv/app
USER wifishare

EXPOSE 8000

# Migrations are applied here rather than in an init container: this service
# is the only writer of its schema.
CMD ["sh", "-c", "python manage.py migrate --noinput && exec gunicorn config.wsgi:application --bind 0.0.0.0:8000 --workers 3 --access-logfile /dev/null"]
