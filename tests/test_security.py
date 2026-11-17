"""Negative tests linked to SEC-01 through SEC-06 in docs/security-tests.md."""

import asyncio
from datetime import datetime, timedelta, timezone
import hashlib
import re
import smtplib
from urllib.parse import parse_qs, urlsplit

import pytest
from sqlalchemy import func, select, text

from models import EmailVerificationToken, User

PASSWORD = "Example1234"


async def create_user(system, email="visitor@example.com", verified=False):
    password_hash = system.module.password_hasher.hash(PASSWORD)
    async with system.session.begin() as session:
        user = User(email=email, password_hash=password_hash, email_verified=verified)
        session.add(user)
        await session.flush()
        return user.id, password_hash


async def create_token(system, user_id, expired=False):
    token, token_hash, expires_at = system.module.generate_verification_token()
    if expired:
        expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    async with system.session.begin() as session:
        session.add(EmailVerificationToken(
            user_id=user_id, token_hash=token_hash, expires_at=expires_at,
        ))
    return token


async def state(system, user_id):
    async with system.session() as session:
        user = await session.get(User, user_id)
        count = await session.scalar(
            select(func.count()).select_from(EmailVerificationToken).where(
                EmailVerificationToken.user_id == user_id
            )
        )
        return user.email_verified, count


def token_from_mail(message):
    link = re.search(r"https?://\S+", message[2]).group(0)
    return parse_qs(urlsplit(link).query)["token"][0]


async def login(client, email="visitor@example.com"):
    page = await client.get("/login")
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
    return await client.post("/login", data={
        "email": email, "password": PASSWORD, "csrf_token": csrf,
    })


@pytest.mark.security("SEC-01")
@pytest.mark.parametrize("verified", [False, True], ids=["pending", "confirmed"])
async def test_existing_email_does_not_overwrite_account(system, verified):
    user_id, original_hash = await create_user(system, verified=verified)
    async with system.client() as client:
        response = await client.post("/register", data={
            "email": "visitor@example.com", "password": "Different1234",
            "password_check": "Different1234",
        })
        assert response.status_code == 400
        assert "уже зарегистрирован" in response.text
    async with system.session() as session:
        users = (await session.scalars(select(User))).all()
        assert len(users) == 1
        assert users[0].id == user_id
        assert users[0].password_hash == original_hash
        assert users[0].email_verified is verified
    assert system.mail.messages == []


@pytest.mark.security("SEC-02")
async def test_unverified_account_cannot_login_or_open_account(system):
    user_id, _ = await create_user(system)
    async with system.client() as client:
        response = await login(client)
        assert response.status_code == 403
        assert "Сначала подтвердите" in response.text
        account = await client.get("/account")
        assert account.status_code == 303
        assert account.headers["location"] == "/login"
    assert await state(system, user_id) == (False, 0)


@pytest.mark.security("SEC-02", "SEC-03")
async def test_expired_link_does_not_activate_account(system):
    user_id, _ = await create_user(system)
    token = await create_token(system, user_id, expired=True)
    async with system.client() as client:
        response = await client.get("/verify-email", params={"token": token})
        assert response.status_code == 400
        assert "Срок действия ссылки" in response.text
        assert await state(system, user_id) == (False, 0)
        assert (await login(client)).status_code == 403
        assert (await client.get("/verify-email", params={"token": token})).status_code == 400


@pytest.mark.security("SEC-03")
async def test_replaced_link_is_rejected(system):
    user_id, _ = await create_user(system)
    old_token = await create_token(system, user_id)
    async with system.client() as client:
        response = await client.post("/resend-verification", data={"email": "visitor@example.com"})
        assert response.status_code == 200
        new_token = token_from_mail(system.mail.messages[-1])
        assert new_token != old_token
        assert (await client.get("/verify-email", params={"token": old_token})).status_code == 400
        assert await state(system, user_id) == (False, 1)
        assert (await client.get("/verify-email", params={"token": new_token})).status_code == 200
        assert await state(system, user_id) == (True, 0)


@pytest.mark.security("SEC-03")
async def test_used_link_cannot_be_replayed(system):
    user_id, _ = await create_user(system)
    token = await create_token(system, user_id)
    async with system.client() as client:
        assert (await client.get("/verify-email", params={"token": token})).status_code == 200
        assert (await client.get("/verify-email", params={"token": token})).status_code == 400
    assert await state(system, user_id) == (True, 0)


async def wait_for_blocked_requests(system, tasks, expected):
    """Observe real PostgreSQL lock waits, not just simultaneous Python tasks."""
    deadline = asyncio.get_running_loop().time() + 10
    while asyncio.get_running_loop().time() < deadline:
        if any(task.done() for task in tasks):
            raise AssertionError("Request finished before the held lock was released")
        async with system.admin.connect() as connection:
            count = await connection.scalar(text(
                "SELECT count(*) FROM pg_stat_activity "
                "WHERE application_name = :name AND wait_event_type = 'Lock'"
            ), {"name": system.schema})
        if count >= expected:
            return
        await asyncio.sleep(0.02)
    raise AssertionError("Concurrent requests did not reach PostgreSQL lock waits")


async def run_race(system, lock_sql, requests):
    tasks = []
    try:
        async with system.session.begin() as blocker:
            await blocker.execute(text(lock_sql))
            for index, request in enumerate(requests, 1):
                tasks.append(asyncio.create_task(request()))
                await wait_for_blocked_requests(system, tasks, index)
        return await asyncio.wait_for(asyncio.gather(*tasks), timeout=25)
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


@pytest.mark.security("SEC-01", "SEC-04")
async def test_concurrent_registration_creates_one_account(system):
    async def register():
        async with system.client() as client:
            return await client.post("/register", data={
                "email": "visitor@example.com", "password": PASSWORD, "password_check": PASSWORD,
            })
    responses = await run_race(system, "LOCK TABLE users IN SHARE MODE", [register, register])
    assert sorted(response.status_code for response in responses) == [303, 400]
    async with system.session() as session:
        users = (await session.scalars(select(User))).all()
        assert len(users) == 1
        assert await state(system, users[0].id) == (False, 1)
    assert len(system.mail.messages) == 1


@pytest.mark.security("SEC-03", "SEC-04")
async def test_concurrent_confirmation_consumes_token_once(system):
    user_id, _ = await create_user(system)
    token = await create_token(system, user_id)
    async def confirm():
        async with system.client() as client:
            return await client.get("/verify-email", params={"token": token})
    responses = await run_race(system, f"SELECT id FROM users WHERE id = {user_id} FOR UPDATE", [confirm, confirm])
    assert sorted(response.status_code for response in responses) == [200, 400]
    assert await state(system, user_id) == (True, 0)


@pytest.mark.security("SEC-03", "SEC-04")
async def test_concurrent_resend_leaves_one_active_token(system):
    user_id, _ = await create_user(system)
    old_token = await create_token(system, user_id)
    async def resend():
        async with system.client() as client:
            return await client.post("/resend-verification", data={"email": "visitor@example.com"})
    responses = await run_race(system, f"SELECT id FROM users WHERE id = {user_id} FOR UPDATE", [resend, resend])
    assert [response.status_code for response in responses] == [200, 200]
    assert await state(system, user_id) == (False, 1)
    assert len(system.mail.messages) == 2
    async with system.client() as client:
        assert (await client.get("/verify-email", params={"token": old_token})).status_code == 400
    # Exactly one of the two newly issued links still matches a saved token.
    hashes = {hashlib.sha256(token_from_mail(m).encode()).hexdigest() for m in system.mail.messages}
    async with system.session() as session:
        active = (await session.scalars(select(EmailVerificationToken.token_hash))).all()
        assert len(active) == 1 and active[0] in hashes


@pytest.mark.security("SEC-02", "SEC-03", "SEC-04")
@pytest.mark.parametrize("first", ["confirm", "resend"])
async def test_confirmation_and_resend_have_consistent_result(system, first):
    user_id, _ = await create_user(system)
    token = await create_token(system, user_id)
    async def confirm():
        async with system.client() as client:
            return await client.get("/verify-email", params={"token": token})
    async def resend():
        async with system.client() as client:
            return await client.post("/resend-verification", data={"email": "visitor@example.com"})
    requests = [confirm, resend] if first == "confirm" else [resend, confirm]
    responses = await run_race(system, f"SELECT id FROM users WHERE id = {user_id} FOR UPDATE", requests)
    confirmation, resent = responses if first == "confirm" else responses[::-1]
    assert resent.status_code == 200
    verified, token_count = await state(system, user_id)
    if verified:
        assert confirmation.status_code == 200
        assert token_count == 0
        assert system.mail.messages == []
    else:
        assert confirmation.status_code == 400
        assert token_count == 1
        assert len(system.mail.messages) == 1
        async with system.client() as client:
            new_token = token_from_mail(system.mail.messages[0])
            assert (await client.get("/verify-email", params={"token": new_token})).status_code == 200


MAIL_ERRORS = [
    pytest.param(lambda: TimeoutError("private-mail-details"), id="timeout"),
    pytest.param(lambda: smtplib.SMTPServerDisconnected("private-mail-details"), id="disconnect"),
    pytest.param(lambda: smtplib.SMTPAuthenticationError(535, b"private-mail-details"), id="authentication"),
]


@pytest.mark.security("SEC-02", "SEC-05", "SEC-06")
@pytest.mark.parametrize("error_factory", MAIL_ERRORS)
async def test_mail_failure_keeps_account_unverified_and_allows_retry(system, error_factory, caplog):
    system.mail.error = error_factory()
    async with system.client() as client:
        response = await client.post("/register", data={
            "email": "visitor@example.com", "password": PASSWORD, "password_check": PASSWORD,
        })
        assert response.status_code == 503
        assert "private-mail-details" not in response.text
        assert "private-mail-details" not in caplog.text
        assert "/resend-verification" in response.text
        async with system.session() as session:
            user_id = await session.scalar(select(User.id))
        assert await state(system, user_id) == (False, 1)
        assert (await login(client)).status_code == 403
        assert (await client.get("/account")).status_code == 303
        system.mail.error = None
        assert (await client.post("/resend-verification", data={"email": "visitor@example.com"})).status_code == 200
        token = token_from_mail(system.mail.messages[-1])
        assert (await client.get("/verify-email", params={"token": token})).status_code == 200
        assert (await login(client)).status_code == 303
        assert (await client.get("/account")).status_code == 200


@pytest.mark.security("SEC-02", "SEC-05", "SEC-06")
async def test_resend_failure_is_neutral_and_can_be_retried(system, caplog):
    user_id, _ = await create_user(system)
    await create_user(system, email="confirmed@example.com", verified=True)
    await create_token(system, user_id)
    system.mail.error = TimeoutError("private-mail-details")
    async with system.client() as client:
        pending = await client.post("/resend-verification", data={"email": "visitor@example.com"})
        unknown = await client.post("/resend-verification", data={"email": "unknown@example.com"})
        confirmed = await client.post("/resend-verification", data={"email": "confirmed@example.com"})
        assert pending.status_code == unknown.status_code == confirmed.status_code == 200
        assert pending.text == unknown.text == confirmed.text
        assert "private-mail-details" not in pending.text + caplog.text
        assert await state(system, user_id) == (False, 1)
        assert (await login(client)).status_code == 403
        system.mail.error = None
        assert (await client.post("/resend-verification", data={"email": "visitor@example.com"})).status_code == 200
        new_token = token_from_mail(system.mail.messages[-1])
        assert (await client.get("/verify-email", params={"token": new_token})).status_code == 200
