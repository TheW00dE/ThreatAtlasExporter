"""Configuration: profiles from a TOML file, overridden by env vars and CLI flags.

Precedence (highest first): CLI flags, environment variables, the selected profile,
built-in defaults.

Token lookup order: ``--token``, ``TAE_TOKEN``, ``TAE_TOKEN_FILE``, the profile's
``token_file``, then the OS keyring (``tae auth login``). Tokens are never read from
the config file itself, so it can be committed or mounted from a ConfigMap.
"""

from __future__ import annotations

import os
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from tae.client.http import normalize_base_url

KEYRING_SERVICE = "threatatlas-exporter"
DEFAULT_TIMEOUT = 30.0
DEFAULT_RETRIES = 3

_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off"}


class ConfigError(Exception):
    """The configuration is missing something or is malformed."""


@dataclass(frozen=True)
class Profile:
    name: str
    url: str | None = None
    verify_tls: bool = True
    ca_bundle: str | None = None
    timeout: float = DEFAULT_TIMEOUT
    retries: int = DEFAULT_RETRIES
    token_file: str | None = None


@dataclass(frozen=True)
class ConfigFile:
    path: Path | None
    default_profile: str | None = None
    profiles: dict[str, Profile] = field(default_factory=dict)


@dataclass(frozen=True)
class Settings:
    """Fully resolved settings for one run."""

    profile: str | None
    url: str
    token: str | None
    token_source: str | None
    verify: bool | str
    timeout: float
    retries: int
    config_path: Path | None

    def client_options(self) -> dict[str, Any]:
        return {"timeout": self.timeout, "verify": self.verify, "retries": self.retries}


@dataclass
class Overrides:
    """Values given on the command line (``None`` means not given)."""

    config: Path | None = None
    profile: str | None = None
    url: str | None = None
    token: str | None = None
    ca_bundle: str | None = None
    verify_tls: bool | None = None
    timeout: float | None = None


def default_config_path(env: Mapping[str, str] | None = None) -> Path:
    env = os.environ if env is None else env
    base = env.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "tae" / "config.toml"


def load_config_file(path: Path | None, *, required: bool = False) -> ConfigFile:
    if path is None or not path.exists():
        if required:
            raise ConfigError(f"Config file not found: {path}")
        return ConfigFile(path=None)
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"Cannot read config file {path}: {exc}") from exc

    profiles: dict[str, Profile] = {}
    raw_profiles = raw.get("profiles", {})
    if not isinstance(raw_profiles, dict):
        raise ConfigError(f"{path}: [profiles] must be a table")
    for name, data in raw_profiles.items():
        if not isinstance(data, dict):
            raise ConfigError(f"{path}: [profiles.{name}] must be a table")
        profiles[name] = _profile_from_dict(name, data, path)

    default = raw.get("default_profile")
    if default is not None and default not in profiles:
        raise ConfigError(f"{path}: default_profile {default!r} is not defined under [profiles]")
    return ConfigFile(path=path, default_profile=default, profiles=profiles)


def _profile_from_dict(name: str, data: dict[str, Any], path: Path) -> Profile:
    known = {"url", "verify_tls", "ca_bundle", "timeout", "retries", "token_file"}
    unknown = set(data) - known
    if "token" in unknown:
        raise ConfigError(
            f"{path}: [profiles.{name}] must not contain a token. "
            "Use TAE_TOKEN, token_file, or `tae auth login` instead."
        )
    if unknown:
        raise ConfigError(f"{path}: [profiles.{name}] has unknown keys: {', '.join(sorted(unknown))}")
    try:
        return Profile(
            name=name,
            url=data.get("url"),
            verify_tls=bool(data.get("verify_tls", True)),
            ca_bundle=data.get("ca_bundle"),
            timeout=float(data.get("timeout", DEFAULT_TIMEOUT)),
            retries=int(data.get("retries", DEFAULT_RETRIES)),
            token_file=data.get("token_file"),
        )
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"{path}: [profiles.{name}]: {exc}") from exc


def resolve(overrides: Overrides, env: Mapping[str, str] | None = None) -> Settings:
    """Combine CLI flags, env vars and the config file into ``Settings``."""
    env = os.environ if env is None else env

    explicit_path = overrides.config or (Path(env["TAE_CONFIG"]) if env.get("TAE_CONFIG") else None)
    cfg = load_config_file(explicit_path or default_config_path(env), required=explicit_path is not None)

    profile_name = overrides.profile or env.get("TAE_PROFILE") or cfg.default_profile
    if profile_name and profile_name not in cfg.profiles:
        where = cfg.path or default_config_path(env)
        raise ConfigError(f"Profile {profile_name!r} is not defined in {where}")
    profile = cfg.profiles.get(profile_name or "", Profile(name=profile_name or "default"))

    url = overrides.url or env.get("TAE_URL") or profile.url
    if not url:
        raise ConfigError(
            "No ThreatAtlas URL configured. Pass --url, set TAE_URL, or add a profile to "
            f"{cfg.path or default_config_path(env)}."
        )
    try:
        url = normalize_base_url(url)
    except ValueError as exc:
        raise ConfigError(str(exc)) from exc

    verify_tls = overrides.verify_tls
    if verify_tls is None and env.get("TAE_VERIFY_TLS"):
        verify_tls = _parse_bool(env["TAE_VERIFY_TLS"], "TAE_VERIFY_TLS")
    if verify_tls is None:
        verify_tls = profile.verify_tls
    ca_bundle = overrides.ca_bundle or env.get("TAE_CA_BUNDLE") or profile.ca_bundle
    verify: bool | str
    if not verify_tls:
        verify = False
    elif ca_bundle:
        ca_path = Path(ca_bundle).expanduser()
        if not ca_path.is_file():
            raise ConfigError(f"CA bundle not found: {ca_path}")
        verify = str(ca_path)
    else:
        verify = True

    timeout = overrides.timeout
    if timeout is None and env.get("TAE_TIMEOUT"):
        try:
            timeout = float(env["TAE_TIMEOUT"])
        except ValueError as exc:
            raise ConfigError(f"TAE_TIMEOUT must be a number, got {env['TAE_TIMEOUT']!r}") from exc

    token, source = resolve_token(overrides.token, env, profile, url)
    return Settings(
        profile=profile_name,
        url=url,
        token=token,
        token_source=source,
        verify=verify,
        timeout=timeout if timeout is not None else profile.timeout,
        retries=profile.retries,
        config_path=cfg.path,
    )


def resolve_token(
    cli_token: str | None, env: Mapping[str, str], profile: Profile, url: str
) -> tuple[str | None, str | None]:
    if cli_token:
        return cli_token.strip(), "--token"
    if env.get("TAE_TOKEN"):
        return env["TAE_TOKEN"].strip(), "TAE_TOKEN"
    for source, file in (("TAE_TOKEN_FILE", env.get("TAE_TOKEN_FILE")), ("token_file", profile.token_file)):
        if file:
            path = Path(file).expanduser()
            try:
                file_token = path.read_text(encoding="utf-8").strip()
            except OSError as exc:
                raise ConfigError(f"Cannot read token file {path}: {exc}") from exc
            if not file_token:
                raise ConfigError(f"Token file {path} ({source}) is empty")
            return file_token, f"{source} ({path})"
    token = keyring_get(url)
    if token:
        return token, "keyring"
    return None, None


def _parse_bool(value: str, name: str) -> bool:
    v = value.strip().lower()
    if v in _TRUE:
        return True
    if v in _FALSE:
        return False
    raise ConfigError(f"{name} must be true or false, got {value!r}")


# ── Keyring (optional dependency, workstation use) ───────────────────────────────


def _keyring() -> Any:
    try:
        import keyring
    except ImportError:
        return None
    return keyring


def keyring_available() -> bool:
    return _keyring() is not None


def keyring_get(url: str) -> str | None:
    kr = _keyring()
    if kr is None:
        return None
    try:
        value = kr.get_password(KEYRING_SERVICE, url)
    except Exception:  # no usable backend (common in containers)
        return None
    return str(value) if value else None


def keyring_set(url: str, token: str) -> None:
    kr = _keyring()
    if kr is None:
        raise ConfigError(
            "Keyring support is not installed. Install with: pip install 'threatatlas-exporter[keyring]'"
        )
    try:
        kr.set_password(KEYRING_SERVICE, url, token)
    except Exception as exc:
        raise ConfigError(f"Could not store the token in the OS keyring: {exc}") from exc


def keyring_delete(url: str) -> bool:
    kr = _keyring()
    if kr is None:
        return False
    try:
        kr.delete_password(KEYRING_SERVICE, url)
    except Exception:
        return False
    return True
