"""Настройки приложения и отправки почты из локального файла .env."""

import os
from pathlib import Path
from urllib.parse import urlencode, urlsplit

from dotenv import load_dotenv

load_dotenv(Path(__file__).with_name(".env"))


def required(name: str, *, strip: bool = True) -> str:
    value = os.environ.get(name, "")
    if not value.strip():
        raise RuntimeError(f"Заполните {name} в файле .env.")
    return value.strip() if strip else value


def port(name: str) -> int:
    try:
        value = int(required(name))
    except ValueError:
        raise RuntimeError(f"{name} в файле .env должен быть числом.") from None
    if not 1 <= value <= 65535:
        raise RuntimeError(f"{name} должен быть от 1 до 65535.")
    return value


APP_HOST = required("APP_HOST")
APP_PORT = port("APP_PORT")
APP_BASE_URL = required("APP_BASE_URL").rstrip("/")
site_url = urlsplit(APP_BASE_URL)
if (
    site_url.scheme not in {"http", "https"}
    or not site_url.hostname
    or site_url.username is not None
    or site_url.password is not None
    or site_url.query
    or site_url.fragment
):
    raise RuntimeError("APP_BASE_URL должен быть адресом сайта с http:// или https://.")

SMTP_HOST = required("SMTP_HOST")
SMTP_PORT = port("SMTP_PORT")
SMTP_USERNAME = required("SMTP_USERNAME")
SMTP_PASSWORD = required("SMTP_PASSWORD", strip=False)
SMTP_FROM = os.environ.get("SMTP_FROM", "").strip() or SMTP_USERNAME
SMTP_SECURITY = required("SMTP_SECURITY").lower()
if SMTP_SECURITY not in {"ssl", "starttls"}:
    raise RuntimeError("SMTP_SECURITY в .env должен быть ssl или starttls.")


def verification_url(token: str) -> str:
    return f"{APP_BASE_URL}/verify-email?{urlencode({'token': token})}"
