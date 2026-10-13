"""Strict exact-host authorization and conservative scan limits."""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from pathlib import Path


class ScopeError(ValueError):
    """Invalid or missing authorization configuration."""


def normalize_target(value: str) -> str:
    if not isinstance(value, str):
        raise ScopeError("Targets must be hostnames or IP addresses.")
    value = value.strip().rstrip(".")
    if not value or any(char in value for char in "/:@?#[]") or "*" in value:
        raise ScopeError(f"Invalid target {value!r}; provide one hostname or IP, not a URL or wildcard.")
    try:
        return ipaddress.ip_address(value).compressed
    except ValueError:
        try:
            hostname = value.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise ScopeError(f"Invalid hostname {value!r}.") from exc
        if len(hostname) > 253 or any(
            not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
            for label in hostname.split(".")
        ):
            raise ScopeError(f"Invalid hostname {value!r}.")
        return hostname


@dataclass(frozen=True)
class Scope:
    targets: frozenset[str]
    rate_limit_rps: float = 0.5
    max_ports: int = 100

    def permits(self, target: str) -> bool:
        return normalize_target(target) in self.targets


def load_scope(path: str | Path) -> Scope:
    try:
        with Path(path).open(encoding="utf-8") as stream:
            config = json.load(stream)
    except (OSError, json.JSONDecodeError) as exc:
        raise ScopeError(f"Cannot read scope configuration {path}: {exc}") from exc
    if not isinstance(config, dict) or config.get("authorized") is not True:
        raise ScopeError('Scope must explicitly contain "authorized": true.')
    targets = config.get("targets")
    if not isinstance(targets, list) or not targets:
        raise ScopeError("Scope must contain a non-empty targets list.")
    normalized = frozenset(normalize_target(target) for target in targets)
    rate = config.get("rate_limit_rps", 0.5)
    if isinstance(rate, bool) or not isinstance(rate, (int, float)) or not 0.1 <= rate <= 1.0:
        raise ScopeError("rate_limit_rps must be between 0.1 and 1.0.")
    ports = config.get("max_ports", 100)
    if isinstance(ports, bool) or not isinstance(ports, int) or not 1 <= ports <= 1000:
        raise ScopeError("max_ports must be an integer between 1 and 1000.")
    return Scope(normalized, float(rate), ports)
