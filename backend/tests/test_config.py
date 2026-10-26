import secrets

import pytest

from backend.app.config import Settings


def configure_valid_production(monkeypatch, **overrides):
    values = {
        "APP_ENV": "production",
        "APP_ACCESS_PASSWORD": "a-valid-test-password-for-production",
        "APP_AUTH_SECRET": secrets.token_urlsafe(48),
        "FRONTEND_CORS_ORIGINS": "https://nmap-automator.example.app",
        "SCAN_TARGET_ALLOWLIST": "authorized.example,192.0.2.10",
    }
    values.update(overrides)
    for name, value in values.items():
        monkeypatch.setenv(name, value)
    return values


def test_production_accepts_high_entropy_credentials_and_explicit_origins(monkeypatch):
    values = configure_valid_production(
        monkeypatch,
        APP_AUTH_SECRET=f"ordinary-words-in-a-valid-secret-{secrets.token_urlsafe(48)}",
        FRONTEND_CORS_ORIGINS="https://nmap-automator.example.app,https://admin.example.app:8443",
    )

    settings = Settings.from_environment()

    assert settings.app_access_password == values["APP_ACCESS_PASSWORD"]
    assert settings.app_auth_secret == values["APP_AUTH_SECRET"]
    assert settings.cors_origins == (
        "https://nmap-automator.example.app",
        "https://admin.example.app:8443",
    )


@pytest.mark.parametrize(
    "setting,value",
    [
        ("APP_ACCESS_PASSWORD", "replace-with-a-long-local-password"),
        ("APP_ACCESS_PASSWORD", "change-me-and-use-a-random-password"),
        ("APP_ACCESS_PASSWORD", "your-secret-is-this-known-password"),
        ("APP_ACCESS_PASSWORD", "your-private-local-password"),
        ("APP_ACCESS_PASSWORD", "example-password-for-deployment"),
        ("APP_AUTH_SECRET", "replace-with-at-least-32-random-bytes"),
        ("APP_AUTH_SECRET", "change-me-and-use-a-random-secret-1234567890"),
        ("APP_AUTH_SECRET", "your-secret-here-please-use-a-long-random-value"),
        ("APP_AUTH_SECRET", "your-private-local-random-secret-at-least-32-bytes"),
        ("APP_AUTH_SECRET", "this-secret-placeholder-is-long-enough-but-known"),
    ],
)
def test_production_rejects_placeholder_credentials(monkeypatch, setting, value):
    configure_valid_production(monkeypatch, **{setting: value})

    with pytest.raises(ValueError, match=setting):
        Settings.from_environment()


@pytest.mark.parametrize(
    "secret",
    [None, "short-secret", "a" * 48],
)
def test_production_rejects_missing_short_or_low_entropy_signing_secrets(monkeypatch, secret):
    overrides = {"APP_AUTH_SECRET": "" if secret is None else secret}
    configure_valid_production(monkeypatch, **overrides)

    with pytest.raises(ValueError, match="APP_AUTH_SECRET"):
        Settings.from_environment()


def test_production_rejects_missing_or_placeholder_password(monkeypatch):
    configure_valid_production(monkeypatch, APP_ACCESS_PASSWORD="")

    with pytest.raises(ValueError, match="APP_ACCESS_PASSWORD"):
        Settings.from_environment()


@pytest.mark.parametrize("origins", ["", "   "])
def test_production_rejects_missing_cors_origins(monkeypatch, origins):
    configure_valid_production(monkeypatch, FRONTEND_CORS_ORIGINS=origins)

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
    configure_valid_production(monkeypatch, FRONTEND_CORS_ORIGINS=origin)

    with pytest.raises(ValueError, match="FRONTEND_CORS_ORIGINS"):
        Settings.from_environment()


def test_production_rejects_missing_target_allowlist(monkeypatch):
    configure_valid_production(monkeypatch, SCAN_TARGET_ALLOWLIST="")

    with pytest.raises(ValueError, match="SCAN_TARGET_ALLOWLIST"):
        Settings.from_environment()


def test_development_keeps_localhost_http_origin(monkeypatch):
    monkeypatch.setenv("APP_ENV", "development")
    monkeypatch.setenv("FRONTEND_CORS_ORIGINS", "http://localhost:5173")

    assert Settings.from_environment().cors_origins == ("http://localhost:5173",)
