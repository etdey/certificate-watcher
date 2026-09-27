"""
Configuration module for the certificate watcher.
"""

import os
import pathlib
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Protocol

import yaml


class _Readable(Protocol):
    def read(self) -> str: ...


@dataclass
class WatchTarget:
    id: str
    host: str
    port: int
    description: str = ""
    starttls: str | None = None
    strict: bool = False


@dataclass
class AlertConfig:
    warning_days: int = 30
    critical_days: int = 10

    def __post_init__(self):
        if self.warning_days <= self.critical_days:
            raise ValueError("warning_days must be greater than critical_days")


@dataclass
class EmailNotification:
    # discriminator kept for cheap future extension to other notification types
    type: str
    from_address: str
    to_address: str
    from_name: str = ""
    to_name: str = ""


@dataclass
class NotificationsConfig:
    destinations: list[EmailNotification] = field(default_factory=list)


@dataclass
class AppConfig:
    watch: list[WatchTarget] = field(default_factory=list)
    alerts: AlertConfig = field(default_factory=AlertConfig)
    notifications: NotificationsConfig = field(default_factory=NotificationsConfig)


def _load_document(source: str | os.PathLike | _Readable) -> dict:
    # Look for a path-like configuration source.
    if isinstance(source, os.PathLike):
        with pathlib.Path(source).open(encoding="utf-8") as config_file:
            document = yaml.safe_load(config_file)
    # Treat strings as file paths when they exist, otherwise as YAML text.
    elif isinstance(source, str):
        path = pathlib.Path(source)
        # Look for a string containing an existing configuration file path.
        if path.is_file():
            with path.open(encoding="utf-8") as config_file:
                document = yaml.safe_load(config_file)
        else:
            document = yaml.safe_load(source)
    # Look for a readable file-like object.
    elif hasattr(source, "read"):
        document = yaml.safe_load(source.read())
    else:
        raise TypeError("source must be a path, YAML string, or file-like object")

    # Require the parsed configuration to be a top-level mapping.
    if not isinstance(document, Mapping):
        raise ValueError("configuration must contain a YAML mapping")

    return dict(document)


def _build_watch_targets(entries: list) -> list[WatchTarget]:
    targets = []
    for index, entry in enumerate(entries):
        missing = [key for key in ("id", "host", "port") if key not in entry]
        if missing:
            raise ValueError(f"watch entry {index} ({entry.get('id', '?')!r}) is missing required field(s): {', '.join(missing)}")
        targets.append(
            WatchTarget(
                id=entry["id"],
                host=entry["host"],
                port=entry["port"],
                description=entry.get("description", ""),
                starttls=entry.get("starttls"),
                strict=entry.get("unsafe_validation", False),
            )
        )
    return targets


def _build_alert_config(section: dict) -> AlertConfig:
    return AlertConfig(
        warning_days=section.get("warning_days", 30),
        critical_days=section.get("critical_days", 10),
    )


def _build_notifications_config(section: dict) -> NotificationsConfig:
    sources = section.get("source", {})
    destinations = []
    for index, entry in enumerate(section.get("destinations", [])):
        notification_type = entry.get("type")
        # only "email" is implemented; other types will need their own dataclass and branch here
        if notification_type != "email":
            raise ValueError(f"destination {index} has unsupported notification type: {notification_type!r}")

        source_entry = sources.get(notification_type)
        if source_entry is None:
            raise ValueError(f"destination {index} has no matching notifications.source.{notification_type} entry")

        from_address = source_entry.get("address")
        to_address = entry.get("address")
        if not from_address:
            raise ValueError(f"notifications.source.{notification_type} is missing required field: address")
        if not to_address:
            raise ValueError(f"destination {index} is missing required field: address")

        destinations.append(
            EmailNotification(
                type=notification_type,
                from_address=from_address,
                to_address=to_address,
                from_name=source_entry.get("from", ""),
                to_name=entry.get("to", ""),
            )
        )
    return NotificationsConfig(destinations=destinations)


def _parse_config(document: dict) -> AppConfig:
    return AppConfig(
        watch=_build_watch_targets(document.get("watch", [])),
        alerts=_build_alert_config(document.get("config", {})),
        notifications=_build_notifications_config(document.get("notifications", {})),
    )


def read_config(source: str | os.PathLike | _Readable) -> AppConfig:
    return _parse_config(_load_document(source))
