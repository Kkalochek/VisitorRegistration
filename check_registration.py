"""Проверка обработчиков VisitorRegistration из коммита eef0603.

Запуск из папки с запиской:
../VisitorRegistration/.venv/bin/python check_registration.py

Другой путь к репозиторию можно передать через --repo.
Нужны зависимости проекта. PostgreSQL, Gmail и реальные учётные данные не используются.
"""

import argparse
import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from hashlib import sha256
from http.cookies import SimpleCookie
import importlib
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from urllib.parse import urlencode, urlsplit

from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import sessionmaker

COMMIT = "eef0603f4b2a5c846e719cf8fc3ff74067d076f2"
EMAIL = "visitor@example.com"
PASSWORD = "SamplePass123"
COOKIE_NAME = "visitor_session"


class SessionAdapter:
    """Асинхронный интерфейс приложения поверх локальной тестовой сессии."""

    def __init__(self, session, token_model):
        self.session = session
        self.token_model = token_model

    async def scalar(self, statement):
        row = self.session.scalar(statement)
        if isinstance(row, self.token_model) and row.expires_at.tzinfo is None:
            row.expires_at = row.expires_at.replace(tzinfo=timezone.utc)
        return row

    async def get(self, model, key):
        return self.session.get(model, key)

    async def execute(self, statement):
        return self.session.execute(statement)

    async def delete(self, row):
        self.session.delete(row)

    def add(self, row):
        self.session.add(row)

    async def commit(self):
        self.session.commit()

    @asynccontextmanager
    async def begin_nested(self):
        with self.session.begin_nested():
            yield


class SessionFactory:
    def __init__(self, sessions, token_model):
        self.sessions = sessions
        self.token_model = token_model

    @asynccontextmanager
    async def __call__(self):
        with self.sessions() as session:
            yield SessionAdapter(session, self.token_model)

    @asynccontextmanager
    async def begin(self):
        with self.sessions.begin() as session:
            yield SessionAdapter(session, self.token_model)


class VisitorRegistrationChecks(unittest.TestCase):
    def setUp(self):
        engine = create_engine("sqlite://")
        self.addCleanup(engine.dispose)

        @event.listens_for(engine, "connect")
        def enable_foreign_keys(connection, record):
            connection.execute("PRAGMA foreign_keys = ON")

        self.models.Base.metadata.create_all(engine)
        self.sessions = sessionmaker(engine, expire_on_commit=False)
        self.cookies = {}
        self.mail = []

        async def capture_mail(recipient, subject, body):
            self.mail.append((recipient, subject, body))

        self.enterContext(patch.object(
            self.module, "Session",
            SessionFactory(self.sessions, self.models.EmailVerificationToken),
        ))
        self.enterContext(patch.object(self.module, "send_email", capture_mail))

    async def request(self, method, url, data=None):
        parts = urlsplit(url)
        body = urlencode(data or {}).encode()
        headers = [(b"host", b"127.0.0.1:8000")]
        if self.cookies:
            cookie_value = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
            headers.append((b"cookie", cookie_value.encode()))
        if method == "POST":
            headers.extend([
                (b"content-type", b"application/x-www-form-urlencoded"),
                (b"content-length", str(len(body)).encode()),
            ])
        scope = {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": method,
            "scheme": "http",
            "path": parts.path,
            "raw_path": parts.path.encode(),
            "query_string": parts.query.encode(),
            "root_path": "",
            "headers": headers,
            "client": ("127.0.0.1", 40000),
            "server": ("127.0.0.1", 8000),
        }
        output = []

        async def receive():
            return {"type": "http.request", "body": body, "more_body": False}

        async def send(message):
            output.append(message)

        await self.module.app(scope, receive, send)
        response = output[0]
        for key, value in response["headers"]:
            if key == b"set-cookie":
                for name, cookie in SimpleCookie(value.decode()).items():
                    expires = parsedate_to_datetime(cookie["expires"]) if cookie["expires"] else None
                    if cookie["max-age"] == "0" or (expires and expires <= datetime.now(timezone.utc)):
                        self.cookies.pop(name, None)
                    else:
                        self.cookies[name] = cookie.value
        content = b"".join(chunk.get("body", b"") for chunk in output[1:]).decode()
        return response["status"], dict(response["headers"]), content

    def call(self, method, url, data=None):
        return asyncio.run(self.request(method, url, data))

    def register(self, email=EMAIL, password=PASSWORD, repeat=PASSWORD):
        return self.call("POST", "/register", {
            "email": email, "password": password, "password_check": repeat,
        })

    def login(self, email=EMAIL, password=PASSWORD, csrf=None):
        if csrf is None:
            csrf = self.csrf_from("/login")
        return self.call("POST", "/login", {
            "email": email, "password": password, "csrf_token": csrf,
        })

    def csrf_from(self, url):
        status, _, html = self.call("GET", url)
        self.assertEqual(status, 200)
        token = re.search(r'name="csrf_token" value="([^"]+)"', html)
        self.assertIsNotNone(token)
        return token[1]

    def confirmation_url(self):
        link = re.search(r"https?://[^\s]+/verify-email\?token=[^\s]+", self.mail[-1][2])
        self.assertIsNotNone(link)
        return link[0]

    def create_confirmed_user(self):
        self.assertEqual(self.register()[0], 303)
        self.assertEqual(self.call("GET", self.confirmation_url())[0], 200)

    def users(self):
        with self.sessions() as session:
            return list(session.scalars(select(self.models.User)))

    def tokens(self):
        with self.sessions() as session:
            return list(session.scalars(select(self.models.EmailVerificationToken)))

    def test_01_forms(self):
        forms = {
            "/register": "/register",
            "/login": "/login",
            "/resend-verification": "/resend-verification",
        }
        for url, action in forms.items():
            status, _, html = self.call("GET", url)
            self.assertEqual(status, 200)
            self.assertIn(f'action="{action}"', html)

    def test_02_invalid_input(self):
        self.assertEqual(self.register(email="invalid")[0], 422)
        for password, repeat in [
            (PASSWORD, "Different1"),
            ("Short1", "Short1"),
            ("LettersOnly", "LettersOnly"),
        ]:
            self.assertEqual(self.register(password=password, repeat=repeat)[0], 400)
        self.assertEqual(self.users(), [])
        self.assertEqual(self.mail, [])

    def test_03_registration_and_duplicate(self):
        status, headers, _ = self.register()
        self.assertEqual(status, 303)
        self.assertEqual(headers[b"location"], b"/login")
        self.assertEqual(self.register()[0], 400)
        user, = self.users()
        token, = self.tokens()
        self.assertEqual(user.email, EMAIL)
        self.assertFalse(user.email_verified)
        self.assertNotEqual(user.password_hash, PASSWORD)
        self.assertEqual(token.user_id, user.id)
        self.assertEqual(len(self.mail), 1)
        self.assertEqual(self.mail[0][0], EMAIL)

    def test_04_login(self):
        self.assertEqual(self.register()[0], 303)
        self.assertEqual(self.login(password="Incorrect1")[0], 401)
        self.assertEqual(self.login()[0], 403)
        self.assertEqual(self.call("GET", self.confirmation_url())[0], 200)
        status, headers, _ = self.login()
        self.assertEqual(status, 303)
        self.assertEqual(headers[b"location"], b"/account")

    def test_05_csrf(self):
        self.create_confirmed_user()
        self.csrf_from("/login")
        status, _, _ = self.call("POST", "/login", {"email": EMAIL, "password": PASSWORD})
        self.assertEqual(status, 403)
        self.assertEqual(self.login(csrf="другое значение")[0], 403)
        self.assertEqual(self.login()[0], 303)
        valid_csrf = self.csrf_from("/account")
        status, _, _ = self.call("POST", "/logout", {"csrf_token": "incorrect"})
        self.assertEqual(status, 403)
        self.assertEqual(self.call("GET", "/account")[0], 200)
        self.assertEqual(self.call("POST", "/logout", {"csrf_token": valid_csrf})[0], 303)

    def test_06_cookie_and_account(self):
        self.create_confirmed_user()
        self.assertEqual(self.login()[0], 303)
        status, _, html = self.call("GET", "/account")
        self.assertEqual(status, 200)
        self.assertIn(EMAIL, html)
        self.cookies[COOKIE_NAME] += "invalid"
        status, headers, _ = self.call("GET", "/account")
        self.assertEqual(status, 303)
        self.assertEqual(headers[b"location"], b"/login")

    def test_07_logout_and_deleted_user(self):
        self.create_confirmed_user()
        self.assertEqual(self.login()[0], 303)
        csrf = self.csrf_from("/account")
        self.assertEqual(self.call("POST", "/logout", {"csrf_token": csrf})[0], 303)
        self.assertNotIn(COOKIE_NAME, self.cookies)
        self.assertEqual(self.call("GET", "/account")[0], 303)
        self.assertEqual(self.login()[0], 303)
        with self.sessions.begin() as session:
            session.delete(session.scalar(select(self.models.User)))
        status, headers, _ = self.call("GET", "/account")
        self.assertEqual(status, 303)
        self.assertEqual(headers[b"location"], b"/login")

    def test_08_confirmation_and_expiration(self):
        self.assertEqual(self.register()[0], 303)
        link = self.confirmation_url()
        self.assertEqual(self.call("GET", link)[0], 200)
        self.assertTrue(self.users()[0].email_verified)
        self.assertEqual(self.call("GET", link)[0], 400)
        self.assertEqual(self.tokens(), [])
        expired_email = "expired@example.com"
        self.assertEqual(self.register(email=expired_email)[0], 303)
        with self.sessions.begin() as session:
            token = session.scalar(select(self.models.EmailVerificationToken))
            token.expires_at = datetime.now(timezone.utc) - timedelta(seconds=60)
        self.assertEqual(self.call("GET", self.confirmation_url())[0], 400)
        self.assertEqual(self.tokens(), [])
        self.assertFalse(next(user.email_verified for user in self.users() if user.email == expired_email))

    def test_09_resend_confirmation(self):
        self.assertEqual(self.register()[0], 303)
        old_link = self.confirmation_url()
        self.assertEqual(self.call("POST", "/resend-verification", {"email": EMAIL})[0], 200)
        self.assertEqual(len(self.mail), 2)
        new_link = self.confirmation_url()
        self.assertNotEqual(old_link, new_link)
        self.assertEqual(len(self.tokens()), 1)
        self.assertEqual(self.call("GET", old_link)[0], 400)
        self.assertEqual(self.call("GET", new_link)[0], 200)

    def test_10_token_properties(self):
        start = datetime.now(timezone.utc)
        token, digest, expires = self.module.generate_verification_token()
        end = datetime.now(timezone.utc)
        other_token, _, _ = self.module.generate_verification_token()
        self.assertNotEqual(token, other_token)
        self.assertEqual(digest, sha256(token.encode()).hexdigest())
        self.assertRegex(digest, r"^[0-9a-f]{64}$")
        self.assertLessEqual(start + timedelta(hours=24), expires)
        self.assertLessEqual(expires, end + timedelta(hours=24))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parent.parent / "VisitorRegistration")
    args = parser.parse_args()
    with TemporaryDirectory(prefix="registration-check-") as temporary:
        folder = Path(temporary)
        archive = folder / "source.tar"
        subprocess.run(
            ["git", "-C", str(args.repo), "archive", "-o", str(archive), COMMIT],
            check=True,
        )
        with tarfile.open(archive) as source:
            source.extractall(folder, filter="data")
        sys.path.insert(0, str(folder))
        with patch.dict(os.environ, {
            "DB_PASSWORD": "unused-in-test",
            "SESSION_SECRET": "local-checks-only",
        }):
            VisitorRegistrationChecks.module = importlib.import_module("VisitorRegistration")
            VisitorRegistrationChecks.models = importlib.import_module("models")
            print(f"VisitorRegistration {COMMIT[:7]} | Python {sys.version.split()[0]} | ASGI + SQLite", flush=True)
            suite = unittest.defaultTestLoader.loadTestsFromTestCase(VisitorRegistrationChecks)
            result = unittest.TextTestRunner(verbosity=2).run(suite)
        return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
