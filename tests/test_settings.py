"""Configuration: safe defaults, and the DATABASE_URL parser."""

from __future__ import annotations

from pathlib import Path

from django.conf import settings
from django.test import SimpleTestCase

from config.env import database_from_url, get_bool, get_list

BASE = Path("/srv/app")


class DefaultsTest(SimpleTestCase):
    def test_debug_is_off_by_default(self) -> None:
        self.assertFalse(settings.DEBUG)

    def test_allowed_hosts_is_not_a_wildcard(self) -> None:
        self.assertNotIn("*", settings.ALLOWED_HOSTS)

    def test_security_headers_are_set(self) -> None:
        self.assertTrue(settings.SECURE_CONTENT_TYPE_NOSNIFF)
        self.assertEqual(settings.X_FRAME_OPTIONS, "DENY")
        self.assertEqual(settings.SECURE_REFERRER_POLICY, "no-referrer")

    def test_the_spec_directory_is_configurable(self) -> None:
        self.assertTrue(Path(settings.SPEC_DIR).name)


class DatabaseUrlTest(SimpleTestCase):
    def test_sqlite_relative(self) -> None:
        self.assertEqual(
            database_from_url("sqlite:///wifishare.sqlite3", BASE),
            {"ENGINE": "django.db.backends.sqlite3", "NAME": "/srv/app/wifishare.sqlite3"},
        )

    def test_sqlite_absolute(self) -> None:
        self.assertEqual(
            database_from_url("sqlite:////var/lib/wifishare/db.sqlite3", BASE)["NAME"],
            "/var/lib/wifishare/db.sqlite3",
        )

    def test_sqlite_memory(self) -> None:
        self.assertEqual(database_from_url("sqlite://:memory:", BASE)["NAME"], ":memory:")

    def test_postgres(self) -> None:
        parsed = database_from_url("postgres://wifi:s3cr3t@db:5432/wifishare", BASE)
        self.assertEqual(parsed["ENGINE"], "django.db.backends.postgresql")
        self.assertEqual(parsed["NAME"], "wifishare")
        self.assertEqual(parsed["USER"], "wifi")
        self.assertEqual(parsed["PASSWORD"], "s3cr3t")
        self.assertEqual(parsed["HOST"], "db")
        self.assertEqual(parsed["PORT"], "5432")

    def test_percent_encoded_password(self) -> None:
        parsed = database_from_url("postgresql://u:p%40ss%2Fword@db/wifishare", BASE)
        self.assertEqual(parsed["PASSWORD"], "p@ss/word")

    def test_unknown_scheme(self) -> None:
        with self.assertRaises(ValueError):
            database_from_url("mysql://db/wifishare", BASE)


class EnvHelpersTest(SimpleTestCase):
    def test_get_bool(self) -> None:
        import os

        os.environ["WIFISHARE_TEST_FLAG"] = "TRUE"
        self.addCleanup(os.environ.pop, "WIFISHARE_TEST_FLAG")
        self.assertTrue(get_bool("WIFISHARE_TEST_FLAG"))
        self.assertFalse(get_bool("WIFISHARE_TEST_MISSING"))
        self.assertTrue(get_bool("WIFISHARE_TEST_MISSING", True))

    def test_get_list(self) -> None:
        import os

        os.environ["WIFISHARE_TEST_HOSTS"] = "a.example, b.example ,"
        self.addCleanup(os.environ.pop, "WIFISHARE_TEST_HOSTS")
        self.assertEqual(get_list("WIFISHARE_TEST_HOSTS"), ["a.example", "b.example"])


class EnvExampleTest(SimpleTestCase):
    def test_the_env_example_holds_no_real_value(self) -> None:
        example = Path(settings.BASE_DIR) / ".env.example"
        self.assertTrue(example.is_file())
        placeholders = 0
        for line in example.read_text(encoding="utf-8").splitlines():
            if line.startswith(("SECRET_KEY=", "OPTOUT_PEPPER=")):
                self.assertIn("change-me", line.split("=", 1)[1])
                placeholders += 1
        self.assertEqual(placeholders, 2)


class SecretKeyGuardTest(SimpleTestCase):
    """The development key is refused the moment a real host is configured."""

    def _load(self, env: dict[str, str | None]):
        """Re-import settings.py under a different environment."""
        import importlib
        import os

        previous = {name: os.environ.get(name) for name in env}
        for name, value in env.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        try:
            spec = importlib.util.spec_from_file_location(
                "config.settings_probe", Path(settings.BASE_DIR) / "config" / "settings.py"
            )
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module
        finally:
            for name, value in previous.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value

    def test_local_hosts_may_use_the_development_key(self) -> None:
        module = self._load({"ALLOWED_HOSTS": "localhost,127.0.0.1", "SECRET_KEY": None})
        self.assertFalse(module.DEBUG)

    def test_a_real_host_without_a_secret_key_refuses_to_start(self) -> None:
        with self.assertRaises(RuntimeError):
            self._load({"ALLOWED_HOSTS": "api.wifishare.example", "SECRET_KEY": None})

    def test_a_real_host_with_a_secret_key_is_fine(self) -> None:
        module = self._load(
            {"ALLOWED_HOSTS": "api.wifishare.example", "SECRET_KEY": "a-real-key-from-the-env"}
        )
        self.assertEqual(module.ALLOWED_HOSTS, ["api.wifishare.example"])
