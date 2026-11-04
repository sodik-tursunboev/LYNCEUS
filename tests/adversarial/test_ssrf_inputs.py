from ssrf_inputs import SSRF_INPUTS


def test_ssrf_probe_list_is_well_formed() -> None:
    urls = [u for u, _ in SSRF_INPUTS]
    assert len(urls) == len(set(urls)) >= 15
    assert all(u.startswith("http://") and reason for u, reason in SSRF_INPUTS)
