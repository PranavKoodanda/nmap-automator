import secrets

import pytest

from backend.app.config import Settings


def _valid_secret():
    return secrets.token_urlsafe(48)


def configure(monkeypatch, **overrides):
    values = {
        "APP_ENV": "production",
        "APP_AUTH_SECRET": _valid_secret(),
        "FRONTEND_CORS_ORIGINS": "https://nmap-automator.example.app",
        "SCAN_TARGET_ALLOWLIST": "",
    }
    values.update(overrides)
    for name, value in values.items():
        monkeypatch.setenv(name, value)
    monkeypatch.delenv("APP_ACCESS_PASSWORD", raising=False)
    return values


def test_production_accepts_random_secret_and_explicit_frontend_origin(monkeypatch):
    values = configure(
        monkeypatch,
        APP_AUTH_SECRET=f"ordinary-words-in-a-valid-secret-{_valid_secret()}",
        FRONTEND_CORS_ORIGINS="https://nmap-automator.example.app,https://admin.example.app:8443",
    )

    settings = Settings.from_environment()

    assert settings.app_auth_secret == values["APP_AUTH_SECRET"]
    assert settings.cors_origins == (
        "https://nmap-automator.example.app",
        "https://admin.example.app:8443",
    )
    assert settings.scan_target_allowlist == ()


@pytest.mark.parametrize(
    "secret",
    [
        "",
        "replace-with-at-least-32-random-bytes",
        "change-me-and-use-a-random-secret-1234567890",
        "your-private-local-random-secret-at-least-32-bytes",
        "a" * 48,
        "short-secret",
    ],
)
def test_app_auth_secret_is_required_strong_and_not_a_placeholder(monkeypatch, secret):
    configure(monkeypatch, APP_AUTH_SECRET=secret)

    with pytest.raises(ValueError, match="APP_AUTH_SECRET"):
        Settings.from_environment()


@pytest.mark.parametrize("origins", ["", "   "])
def test_production_rejects_missing_cors_origins(monkeypatch, origins):
    configure(monkeypatch, FRONTEND_CORS_ORIGINS=origins)

    with pytest.raises(ValueError, match="FRONTEND_CORS_ORIGINS"):
        Settings.from_environment()


@pytest.mark.parametrize(
    "origin",
    [
        "*",
        "https://*.example.app",
        "https://example.app/path",
        "https://example.app/",
        "https://user:password@example.app",
        "https://example.app:invalid",
        "https://example.app:",
        "http://example.app",
        "not-an-origin",
    ],
)
def test_production_rejects_wildcard_or_malformed_cors_origins(monkeypatch, origin):
    configure(monkeypatch, FRONTEND_CORS_ORIGINS=origin)

    with pytest.raises(ValueError, match="FRONTEND_CORS_ORIGINS"):
        Settings.from_environment()


def test_production_accepts_a_present_static_allowlist_as_an_extra_restriction(monkeypatch):
    configure(monkeypatch, SCAN_TARGET_ALLOWLIST="owned.example,8.8.8.8")

    assert Settings.from_environment().scan_target_allowlist == ("owned.example", "8.8.8.8")


def test_development_keeps_localhost_http_origin_and_requires_signing_secret(monkeypatch):
    monkeypatch.setenv("APP_ENV", "development")
    monkeypatch.setenv("APP_AUTH_SECRET", _valid_secret())
    monkeypatch.setenv("FRONTEND_CORS_ORIGINS", "http://localhost:5173")

    assert Settings.from_environment().cors_origins == ("http://localhost:5173",)


def test_development_still_requires_auth_signing_secret(monkeypatch):
    monkeypatch.setenv("APP_ENV", "development")
    monkeypatch.delenv("APP_AUTH_SECRET", raising=False)

    with pytest.raises(ValueError, match="APP_AUTH_SECRET"):
        Settings.from_environment()
