from __future__ import annotations

from pathlib import Path

import pytest

from tae.config import ConfigError, Overrides, load_config_file, resolve


def write_config(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "config.toml"
    path.write_text(text)
    return path


CONFIG = """
default_profile = "prod"

[profiles.prod]
url = "https://prod.test/"
timeout = 10
retries = 5

[profiles.local]
url = "http://localhost:3001/api"
verify_tls = false
"""


def test_default_profile_from_file(tmp_path: Path) -> None:
    s = resolve(Overrides(config=write_config(tmp_path, CONFIG)), env={})
    assert s.profile == "prod"
    assert s.url == "https://prod.test"
    assert s.timeout == 10
    assert s.retries == 5
    assert s.verify is True
    assert s.token is None


def test_profile_selection_and_url_normalisation(tmp_path: Path) -> None:
    s = resolve(Overrides(config=write_config(tmp_path, CONFIG), profile="local"), env={})
    assert s.url == "http://localhost:3001"
    assert s.verify is False


def test_env_overrides_profile_and_cli_overrides_env(tmp_path: Path) -> None:
    cfg = write_config(tmp_path, CONFIG)
    env = {"TAE_PROFILE": "local", "TAE_URL": "https://env.test", "TAE_TIMEOUT": "5"}
    s = resolve(Overrides(config=cfg), env=env)
    assert (s.profile, s.url, s.timeout) == ("local", "https://env.test", 5.0)
    s = resolve(Overrides(config=cfg, url="https://cli.test", timeout=1), env=env)
    assert (s.url, s.timeout) == ("https://cli.test", 1.0)


def test_config_path_from_env(tmp_path: Path) -> None:
    s = resolve(Overrides(), env={"TAE_CONFIG": str(write_config(tmp_path, CONFIG))})
    assert s.profile == "prod"


def test_default_config_location(tmp_path: Path) -> None:
    (tmp_path / "tae").mkdir()
    (tmp_path / "tae" / "config.toml").write_text(CONFIG)
    s = resolve(Overrides(), env={"XDG_CONFIG_HOME": str(tmp_path)})
    assert s.config_path == tmp_path / "tae" / "config.toml"


def test_works_without_config_file(tmp_path: Path) -> None:
    s = resolve(Overrides(), env={"XDG_CONFIG_HOME": str(tmp_path), "TAE_URL": "https://ta.test"})
    assert s.config_path is None
    assert s.profile is None


def test_explicit_missing_config_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="not found"):
        resolve(Overrides(config=tmp_path / "nope.toml"), env={})


def test_no_url_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="No ThreatAtlas URL"):
        resolve(Overrides(), env={"XDG_CONFIG_HOME": str(tmp_path)})


def test_unknown_profile(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="'staging' is not defined"):
        resolve(Overrides(config=write_config(tmp_path, CONFIG), profile="staging"), env={})


def test_undefined_default_profile(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="default_profile"):
        load_config_file(write_config(tmp_path, 'default_profile = "x"\n'))


def test_token_in_config_file_is_refused(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="must not contain a token"):
        load_config_file(write_config(tmp_path, '[profiles.p]\nurl = "https://a.test"\ntoken = "ta_x"\n'))


def test_unknown_profile_keys(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="unknown keys: urll"):
        load_config_file(write_config(tmp_path, '[profiles.p]\nurll = "https://a.test"\n'))


def test_malformed_toml(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="Cannot read"):
        load_config_file(write_config(tmp_path, "[profiles\n"))


def test_token_precedence(tmp_path: Path) -> None:
    token_file = tmp_path / "token"
    token_file.write_text("ta_from_file\n")
    profile_file = tmp_path / "ptoken"
    profile_file.write_text("ta_from_profile")
    cfg = write_config(tmp_path, f'[profiles.p]\nurl = "https://a.test"\ntoken_file = "{profile_file}"\n')
    base = Overrides(config=cfg, profile="p")

    assert resolve(base, env={}).token == "ta_from_profile"
    assert resolve(base, env={"TAE_TOKEN_FILE": str(token_file)}).token == "ta_from_file"
    s = resolve(base, env={"TAE_TOKEN": "ta_env", "TAE_TOKEN_FILE": str(token_file)})
    assert (s.token, s.token_source) == ("ta_env", "TAE_TOKEN")
    s = resolve(Overrides(config=cfg, profile="p", token="ta_cli"), env={"TAE_TOKEN": "ta_env"})
    assert (s.token, s.token_source) == ("ta_cli", "--token")


def test_keyring_is_last_resort(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeKeyring:
        @staticmethod
        def get_password(service: str, user: str) -> str:
            assert (service, user) == ("threatatlas-exporter", "https://a.test")
            return "ta_keyring"

    monkeypatch.setattr("tae.config._keyring", lambda: FakeKeyring)
    s = resolve(Overrides(url="https://a.test"), env={"XDG_CONFIG_HOME": str(tmp_path)})
    assert (s.token, s.token_source) == ("ta_keyring", "keyring")


def test_unreadable_token_file(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="Cannot read token file"):
        resolve(Overrides(url="https://a.test"), env={"TAE_TOKEN_FILE": str(tmp_path / "missing")})


def test_tls_settings(tmp_path: Path) -> None:
    ca = tmp_path / "ca.pem"
    ca.write_text("-----BEGIN CERTIFICATE-----\n")
    env = {"XDG_CONFIG_HOME": str(tmp_path), "TAE_URL": "https://a.test"}
    assert resolve(Overrides(ca_bundle=str(ca)), env=env).verify == str(ca)
    assert resolve(Overrides(), env={**env, "TAE_VERIFY_TLS": "false"}).verify is False
    assert resolve(Overrides(verify_tls=True), env={**env, "TAE_VERIFY_TLS": "false"}).verify is True
    with pytest.raises(ConfigError, match="CA bundle not found"):
        resolve(Overrides(ca_bundle=str(tmp_path / "missing.pem")), env=env)
    with pytest.raises(ConfigError, match="TAE_VERIFY_TLS"):
        resolve(Overrides(), env={**env, "TAE_VERIFY_TLS": "maybe"})


def test_empty_token_file_is_an_error(tmp_path: Path) -> None:
    empty = tmp_path / "token"
    empty.write_text("\n")
    with pytest.raises(ConfigError, match="is empty"):
        resolve(Overrides(url="https://a.test"), env={"TAE_TOKEN_FILE": str(empty)})
