"""Real PostgreSQL, one disposable schema per test, no production DB or mail."""

import importlib.util
import os
from pathlib import Path
import smtplib
import sys
from types import SimpleNamespace
from uuid import uuid4

import dotenv
import httpx
import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from models import Base  # noqa: E402


def pytest_collection_modifyitems(items):
    for item in items:
        mark = item.get_closest_marker("security")
        if mark is None or not mark.args:
            raise pytest.UsageError(f"Security requirement missing for {item.name}")
        item.user_properties.append(("security_requirement", ", ".join(mark.args)))


@pytest.fixture(scope="session")
def test_database_url():
    # Only the dedicated test file is read; the application's .env is not used.
    dotenv.load_dotenv(ROOT / ".env.test")
    value = os.environ.get("TEST_DATABASE_URL")
    if not value:
        raise pytest.UsageError(
            "Set TEST_DATABASE_URL in .env.test to a PostgreSQL database ending in _test."
        )
    url = make_url(value).set(drivername="postgresql+asyncpg")
    if not url.database or not url.database.endswith("_test"):
        raise pytest.UsageError("Tests require a separate database ending in _test.")
    return url


class MailCapture:
    def __init__(self):
        self.messages = []
        self.error = None

    async def __call__(self, recipient, subject, body):
        if self.error is not None:
            raise self.error
        self.messages.append((recipient, subject, body))


def load_module(monkeypatch, name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, name, module)
    spec.loader.exec_module(module)
    return module


@pytest_asyncio.fixture
async def system(test_database_url, monkeypatch):
    schema = "vr_test_" + uuid4().hex
    admin = create_async_engine(test_database_url, poolclass=NullPool)
    engine = create_async_engine(
        test_database_url,
        connect_args={"server_settings": {
            "search_path": schema,
            "application_name": schema,
            "statement_timeout": "20000",
        }},
        pool_size=10,
        max_overflow=0,
    )
    async with admin.begin() as connection:
        await connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    try:
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)

        # Dummy configuration only. The real .env is neither loaded nor changed.
        monkeypatch.setattr(dotenv, "load_dotenv", lambda *args, **kwargs: False)
        for key, value in {
            "APP_HOST": "localhost", "APP_PORT": "1",
            "APP_BASE_URL": "https://registration.example.test",
            "SMTP_HOST": "unused.invalid", "SMTP_PORT": "1",
            "SMTP_SECURITY": "ssl", "SMTP_USERNAME": "sender@example.com",
            "SMTP_PASSWORD": "test-only-unused", "DB_PASSWORD": "test-only-unused",
            "SESSION_SECRET": "test-only-session-key",
        }.items():
            monkeypatch.setenv(key, value)

        def forbid_smtp(*args, **kwargs):
            raise AssertionError("Tests must not connect to an SMTP server")

        monkeypatch.setattr(smtplib, "SMTP", forbid_smtp)
        monkeypatch.setattr(smtplib, "SMTP_SSL", forbid_smtp)
        load_module(monkeypatch, "config", "config.py")
        database = load_module(monkeypatch, "database", "database.py")
        load_module(monkeypatch, "email_sender", "email_sender.py")
        module = load_module(monkeypatch, "tested_registration", "VisitorRegistration.py")
        sessions = async_sessionmaker(engine, expire_on_commit=False)
        mail = MailCapture()
        monkeypatch.setattr(module, "Session", sessions)
        monkeypatch.setattr(module, "send_email", mail)

        def client():
            return httpx.AsyncClient(
                transport=httpx.ASGITransport(app=module.app),
                base_url="http://testserver",
                follow_redirects=False,
            )

        yield SimpleNamespace(
            module=module, session=sessions, mail=mail, client=client,
            admin=admin, schema=schema,
        )
        await database.engine.dispose()
    finally:
        await engine.dispose()
        async with admin.begin() as connection:
            await connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        await admin.dispose()
