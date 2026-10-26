import pytest

from backend.app.scanner.validation import TargetValidationError, validate_target


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("192.0.2.10", "192.0.2.10"),
        ("2001:db8::1", "2001:db8::1"),
        ("localhost", "localhost"),
        ("Example.COM", "example.com"),
        ("host.example.com.", "host.example.com"),
        ("münich.example", "xn--mnich-kva.example"),
    ],
)
def test_valid_targets_are_normalized(target: str, expected: str) -> None:
    assert validate_target(target) == expected


@pytest.mark.parametrize(
    "target",
    [
        "",
        " example.com",
        "example.com ",
        "https://example.com",
        "example.com/path",
        "127.0.0.1;whoami",
        "127.0.0.1 && whoami",
        "example..com",
        "-example.com",
        "example-.com",
        "999.1.1.1",
        "2001:db8::1/64",
    ],
)
def test_invalid_targets_are_rejected(target: str) -> None:
    with pytest.raises(TargetValidationError):
        validate_target(target)
