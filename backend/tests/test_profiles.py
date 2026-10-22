from backend.app.scanner.profiles import (
    ScanProfile,
    available_profiles,
    get_profile,
)


def test_profiles_are_fixed_and_do_not_accept_extra_arguments() -> None:
    profiles = available_profiles()

    assert {profile.name for profile in profiles} == {
        ScanProfile.QUICK_TCP,
        ScanProfile.BASIC_TCP,
        ScanProfile.FULL_TCP,
        ScanProfile.SERVICE_DETECTION,
        ScanProfile.COMPREHENSIVE_TCP,
        ScanProfile.UDP_TOP_100,
        ScanProfile.TCP_UDP_COMMON,
    }
    assert all("--version-all" not in profile.arguments for profile in profiles)
    assert get_profile(ScanProfile.SERVICE_DETECTION).arguments == (
        "-sT",
        "-sV",
        "--version-light",
        "-p",
        "1-1000",
    )
    assert get_profile(ScanProfile.QUICK_TCP).arguments == ("-sT", "-F")
    assert get_profile(ScanProfile.FULL_TCP).arguments == (
        "-sT",
        "-T4",
        "--max-retries",
        "3",
        "-p-",
    )
    assert get_profile(ScanProfile.COMPREHENSIVE_TCP).arguments == (
        "-sT",
        "-sV",
        "--version-light",
        "-T4",
        "--max-retries",
        "3",
        "-p-",
    )
    assert get_profile(ScanProfile.UDP_TOP_100).arguments == ("-sU", "-F")
    assert get_profile(ScanProfile.TCP_UDP_COMMON).arguments == ("-sT", "-sU", "-F")
