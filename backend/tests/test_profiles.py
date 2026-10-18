from backend.app.scanner.profiles import (
    ScanProfile,
    available_profiles,
    get_profile,
)


def test_profiles_are_fixed_and_do_not_accept_extra_arguments() -> None:
    profiles = available_profiles()

    assert {profile.name for profile in profiles} == {
        ScanProfile.BASIC_TCP,
        ScanProfile.SERVICE_DETECTION,
    }
    assert all("--version-all" not in profile.arguments for profile in profiles)
    assert get_profile(ScanProfile.SERVICE_DETECTION).arguments == (
        "-sT",
        "-sV",
        "--version-light",
        "-p",
        "1-1000",
    )
