import pytest
from scanner.validation import ValidationError, load_allowlist, parse_ports, parse_target, validate_config

A = load_allowlist()


@pytest.mark.parametrize("t", ["8.8.8.8", "1.1.1.1/32", "example.com", "", "10.0.0.0/8", "192.168.1.1; rm -rf /", "2001:4860:4860::8888", "$(id)"])
def test_rejects_bad_targets(t):
    with pytest.raises(ValidationError):
        parse_target(t, A)


def test_accepts_lab_targets():
    assert [str(h) for h in parse_target("192.168.56.0/30", A)] == ["192.168.56.1", "192.168.56.2"]
    assert str(parse_target("::1", A)[0]) == "::1"
    assert str(parse_target("fe80::1", A)[0]) == "fe80::1"


def test_custom_allowlist_is_enforced():
    with pytest.raises(ValidationError):
        parse_target("192.168.1.5", load_allowlist(["10.10.0.0/16"]))


def test_ports():
    assert parse_ports("22,80,9000-9002") == [22, 80, 9000, 9001, 9002]
    assert len(parse_ports("all")) == 65535
    for bad in ["0", "65536", "80-", "a", "22;ls", "9-1", ""]:
        with pytest.raises(ValidationError):
            parse_ports(bad) if bad else parse_ports("")


def test_config_whitelist_and_bounds():
    c = validate_config({"timing": 4, "rm": "-rf", "modules": ["http"]})
    assert "rm" not in c and c["modules"] == ["http"]
    for bad in [{"timing": 9}, {"retries": -1}, {"modules": ["shell"]}, {"http_paths": ["../../etc/passwd"]}, {"vhost": "a b;c"},
                {"tcp": False, "udp": False}, {"knock": {"sequence": list(range(1, 40)), "protected_port": 22}}, {"source_ports": [1, 2, 3, 4, 5, 6]}]:
        with pytest.raises(ValidationError):
            validate_config(bad)
