from p7.notify import NullNotifier, from_env


def test_null_notifier_always_true():
    assert NullNotifier().send("hello")


def test_from_env_default_is_null(monkeypatch):
    for var in ("N8N_WEBHOOK_URL", "TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID"):
        monkeypatch.delenv(var, raising=False)
    assert isinstance(from_env(), NullNotifier)


def test_from_env_prefers_n8n(monkeypatch):
    monkeypatch.setenv("N8N_WEBHOOK_URL", "http://x/webhook")
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "t")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "c")
    n = from_env()
    assert type(n).__name__ == "N8nWebhookNotifier"


def test_from_env_telegram_when_only_tg(monkeypatch):
    monkeypatch.delenv("N8N_WEBHOOK_URL", raising=False)
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "t")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "c")
    n = from_env()
    assert type(n).__name__ == "TelegramNotifier"
