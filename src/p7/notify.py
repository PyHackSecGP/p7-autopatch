"""Outbound Telegram alerts via Bot API or n8n webhook. Fire-and-forget."""
from __future__ import annotations

import logging
import os
from typing import Protocol

import requests

log = logging.getLogger(__name__)


class Notifier(Protocol):
    def send(self, text: str) -> bool: ...


class NullNotifier:
    """No-op notifier for dry-run / tests."""

    def send(self, text: str) -> bool:
        log.info("[notify-skip] %s", text)
        return True


class TelegramNotifier:
    """Direct Telegram Bot API client. Set TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID."""

    def __init__(self, bot_token: str, chat_id: str, timeout: int = 10) -> None:
        self.base = f"https://api.telegram.org/bot{bot_token}"
        self.chat_id = chat_id
        self.timeout = timeout

    def send(self, text: str) -> bool:
        try:
            r = requests.post(
                f"{self.base}/sendMessage",
                json={"chat_id": self.chat_id, "text": text, "parse_mode": "Markdown"},
                timeout=self.timeout,
            )
            r.raise_for_status()
            return True
        except Exception as e:
            log.warning("telegram send failed: %s", e)
            return False


class N8nWebhookNotifier:
    """POST events to an n8n workflow webhook."""

    def __init__(self, url: str, timeout: int = 10) -> None:
        self.url = url
        self.timeout = timeout

    def send(self, text: str) -> bool:
        try:
            r = requests.post(self.url, json={"text": text, "source": "p7-autopatch"}, timeout=self.timeout)
            r.raise_for_status()
            return True
        except Exception as e:
            log.warning("n8n webhook send failed: %s", e)
            return False


def from_env() -> Notifier:
    """Build a notifier from env vars; falls back to NullNotifier."""
    url = os.environ.get("N8N_WEBHOOK_URL")
    if url:
        return N8nWebhookNotifier(url)
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    chat = os.environ.get("TELEGRAM_CHAT_ID")
    if token and chat:
        return TelegramNotifier(token, chat)
    return NullNotifier()
