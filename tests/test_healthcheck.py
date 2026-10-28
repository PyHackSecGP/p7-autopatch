from p7.healthcheck import parse_healthcheck_env


def test_single_host():
    assert parse_healthcheck_env("209:ssh") == {209: ["ssh"]}


def test_multiple_hosts_and_svcs():
    got = parse_healthcheck_env("209:ssh;205:docker,uwsgi;207:docker")
    assert got == {209: ["ssh"], 205: ["docker", "uwsgi"], 207: ["docker"]}


def test_empty_input():
    assert parse_healthcheck_env("") == {}


def test_bad_chunk_ignored():
    assert parse_healthcheck_env("noop;209:ssh") == {209: ["ssh"]}


def test_non_numeric_ctid_ignored():
    assert parse_healthcheck_env("abc:ssh;209:x") == {209: ["x"]}
