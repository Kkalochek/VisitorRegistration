import uvicorn
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse
from pydantic import EmailStr
from pwdlib import PasswordHash
from fastapi.responses import RedirectResponse
from sqlalchemy import select, delete
from sqlalchemy.dialects.postgresql import insert
from starlette.concurrency import run_in_threadpool
from starlette.middleware.sessions import SessionMiddleware
import hashlib
import os
import secrets
from datetime import datetime, timezone
from html import escape

from config import APP_HOST, APP_PORT, verification_url
from database import Session
from models import User, EmailVerificationToken
from email_verification import generate_verification_token
from email_sender import send_email

import logging

from sqlalchemy import select, delete

app = FastAPI()
app.add_middleware(
    SessionMiddleware,
    secret_key=os.environ.get("SESSION_SECRET") or secrets.token_urlsafe(32),
    session_cookie="visitor_session",
    max_age=8 * 60 * 60,
    same_site="lax",
)
password_hasher = PasswordHash.recommended()
dummy_password_hash = password_hasher.hash(secrets.token_urlsafe(32))
logger = logging.getLogger(__name__)


PAGE_STYLES = """
    * {
        box-sizing: border-box;
    }
    body {
        margin: 0;
        background: #f3f5f8;
        color: #1e293b;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        font-size: 15px;
        line-height: 1.6;
    }
    .page {
        width: 100%;
        max-width: 492px;
        margin: 0 auto;
        padding: 64px 24px 40px;
    }
    .brand {
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 12px;
        margin-bottom: 28px;
        color: #1e293b;
        font-size: 15px;
        font-weight: 650;
        line-height: 1.35;
        text-decoration: none;
    }
    .brand-mark {
        display: grid;
        place-items: center;
        width: 40px;
        height: 40px;
        border-radius: 12px;
        background: #2563eb;
        color: white;
        font-size: 23px;
        font-weight: 600;
    }
    .card {
        padding: 32px;
        border: 1px solid #e2e8f0;
        border-radius: 20px;
        background: white;
        box-shadow: 0 8px 32px #1e293b06;
        overflow-wrap: anywhere;
    }
    h1 {
        margin: 0 0 12px;
        font-size: 27px;
        line-height: 1.25;
        letter-spacing: -0.6px;
    }
    p {
        margin: 0 0 20px;
    }
    .intro {
        margin-bottom: 28px;
        color: #64748b;
    }
    label {
        display: block;
        color: #334155;
        font-size: 14px;
        font-weight: 600;
    }
    input:not([type="hidden"]) {
        display: block;
        width: 100%;
        min-height: 48px;
        margin-top: 8px;
        padding: 11px 13px;
        border: 1px solid #cbd5e1;
        border-radius: 10px;
        background: white;
        color: #1e293b;
        font: inherit;
        font-size: 16px;
        font-weight: 400;
    }
    input::placeholder {
        color: #7b879a;
    }
    input:not([type="hidden"]):focus {
        outline: 3px solid #dbeafe;
        border-color: #2563eb;
    }
    .hint {
        display: block;
        margin-top: 8px;
        color: #64748b;
        font-size: 12px;
    }
    button {
        display: block;
        width: 100%;
        min-height: 48px;
        padding: 12px 16px;
        border: 1px solid transparent;
        border-radius: 10px;
        background: #2563eb;
        color: white;
        font: inherit;
        font-weight: 600;
        line-height: 1.4;
        cursor: pointer;
    }
    button:hover {
        background: #1d4ed8;
    }
    .secondary {
        border-color: #cbd5e1;
        background: white;
        color: #334155;
    }
    .secondary:hover {
        background: #f1f5f9;
    }
    a {
        color: #1d4ed8;
        text-decoration: underline;
        text-underline-offset: 3px;
    }
    a:hover {
        color: #1e40af;
    }
    a:focus-visible, button:focus-visible {
        outline: 3px solid #93c5fd;
        outline-offset: 4px;
    }
    .form-links {
        margin: 20px 0 0;
        color: #64748b;
        font-size: 13px;
        text-align: center;
    }
    .account-info {
        display: grid;
        gap: 8px;
        margin-bottom: 28px;
        padding: 18px;
        border: 1px solid #e2e8f0;
        border-radius: 12px;
        background: #f8fafc;
    }
    .field-caption {
        color: #64748b;
        font-size: 12px;
    }
    .verified {
        justify-self: start;
        margin-top: 4px;
        padding: 3px 10px;
        border-radius: 20px;
        background: #dcfce7;
        color: #166534;
        font-size: 12px;
        font-weight: 600;
    }
    .success-message {
        padding: 14px;
        border-radius: 10px;
        background: #f0fdf4;
        color: #166534;
    }
    .card > :last-child {
        margin-bottom: 0;
    }
    @media (max-width: 480px) {
        .page {
            padding: 32px 16px;
        }
        .card {
            padding: 24px;
            border-radius: 16px;
        }
        h1 {
            font-size: 24px;
        }
    }
"""


def render_page(title: str, content: str, status_code: int = 200) -> HTMLResponse:
    return HTMLResponse(
        f"""<!doctype html>
        <html lang="ru">
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>{escape(title)} — Регистрация посетителей</title>
            <style>{PAGE_STYLES}</style>
        </head>
        <body>
            <main class="page">
                <a class="brand" href="/login">
                    <span class="brand-mark" aria-hidden="true">Р</span>
                    <span>Регистрация<br>посетителей</span>
                </a>
                <section class="card" aria-labelledby="page-title">
                    <h1 id="page-title">{escape(title)}</h1>
                    {content}
                </section>
            </main>
        </body>
        </html>""",
        status_code=status_code,
    )


def get_csrf_token(request: Request) -> str:
    if "csrf_token" not in request.session:
        request.session["csrf_token"] = secrets.token_urlsafe(32)
    return request.session["csrf_token"]


@app.get("/login", response_class=HTMLResponse)
def show_login(request: Request):
    csrf_token = get_csrf_token(request)
    return render_page("Вход в аккаунт", f"""
    <p class="intro">Введите почту и пароль, чтобы открыть личный кабинет.</p>
    <form method="post" action="/login">
        <input type="hidden" name="csrf_token" value="{csrf_token}">
        <p>
            <label>
                Электронная почта
                <input type="email" name="email" autocomplete="username" required>
            </label>
        </p>
        <p>
            <label>
                Пароль
                <input type="password" name="password"
                       autocomplete="current-password" required>
            </label>
        </p>
        <button type="submit">Войти</button>
    </form>
    <p class="form-links">Нет аккаунта? <a href="/register">Зарегистрироваться</a></p>
    <p class="form-links"><a href="/resend-verification">Отправить письмо подтверждения повторно</a></p>
    """)


@app.post("/login", response_class=HTMLResponse)
async def login(
    request: Request,
    email: EmailStr = Form(),
    password: str = Form(),
    csrf_token: str = Form(default=""),
):
    expected_token = request.session.get("csrf_token", "")
    if not expected_token or not secrets.compare_digest(
        expected_token.encode("utf-8"), csrf_token.encode("utf-8")
    ):
        return render_page(
            "Вход в аккаунт",
            '<p>Форма устарела. Откройте страницу входа заново.</p>'
            '<p><a href="/login">Перейти ко входу</a></p>',
            status_code=403,
        )

    async with Session() as session:
        user = await session.scalar(
            select(User).where(User.email == str(email))
        )

        stored_hash = user.password_hash if user is not None else dummy_password_hash
        password_valid = await run_in_threadpool(
            password_hasher.verify, password, stored_hash
        )

        if user is None or not password_valid:
            return render_page(
                "Вход в аккаунт",
                '<p>Неверная почта или пароль.</p>'
                '<p><a href="/login">Попробовать снова</a></p>',
                status_code=401,
            )

        if not user.email_verified:
            return render_page(
                "Вход в аккаунт",
                '<p>Сначала подтвердите электронную почту.</p>'
                '<p><a href="/resend-verification">Отправить письмо повторно</a></p>'
                '<p><a href="/login">Вернуться ко входу</a></p>',
                status_code=403,
            )

        user_id = user.id

    request.session.clear()
    request.session["user_id"] = user_id
    return RedirectResponse(url="/account", status_code=303)


@app.get("/account", response_class=HTMLResponse)
async def show_account(request: Request):
    user_id = request.session.get("user_id")
    if user_id is None:
        return RedirectResponse(url="/login", status_code=303)

    async with Session() as session:
        user = await session.get(User, user_id)
        if user is None or not user.email_verified:
            request.session.clear()
            return RedirectResponse(url="/login", status_code=303)
        email = user.email

    csrf_token = get_csrf_token(request)
    return render_page(
        "Личный кабинет",
        '<p class="intro">Вы вошли в свой аккаунт.</p>'
        '<div class="account-info">'
        '<span class="field-caption">Электронная почта</span>'
        f'<strong>{escape(email)}</strong>'
        '<span class="verified">Почта подтверждена</span>'
        '</div>'
        '<form method="post" action="/logout">'
        f'<input type="hidden" name="csrf_token" value="{csrf_token}">'
        '<button type="submit" class="secondary">Выйти из аккаунта</button>'
        '</form>'
    )


@app.post("/logout", response_class=HTMLResponse)
async def logout(request: Request, csrf_token: str = Form(default="")):
    expected_token = request.session.get("csrf_token", "")
    if not expected_token or not secrets.compare_digest(
        expected_token.encode("utf-8"), csrf_token.encode("utf-8")
    ):
        return render_page(
            "Выход из аккаунта",
            '<p>Форма устарела. Откройте личный кабинет заново.</p>'
            '<p><a href="/account">Перейти в личный кабинет</a></p>',
            status_code=403,
        )

    request.session.clear()
    return RedirectResponse(url="/login", status_code=303)

@app.get("/resend-verification", response_class=HTMLResponse)
def show_resend_verification():
    return render_page("Новое письмо", """
    <p class="intro">Введите почту, указанную при регистрации.
        Мы отправим новую ссылку для подтверждения.</p>
    <form method="post" action="/resend-verification">
        <p>
            <label>
                Электронная почта
                <input type="email" name="email" autocomplete="email"
                       placeholder="name@example.com" required>
            </label>
        </p>
        <button type="submit">Отправить письмо повторно</button>
    </form>
    <p class="form-links"><a href="/login">Вернуться ко входу</a></p>
    """)

@app.post("/resend-verification", response_class=HTMLResponse)
async def resend_verification(email: EmailStr = Form()):
    message = (
        "Если адрес зарегистрирован и ещё не подтверждён, "
        "мы попробуем отправить письмо с новой ссылкой."
    )

    async with Session() as session:
        user = await session.scalar(
            select(User).where(User.email == str(email))
        )

        if user is None or user.email_verified:
            return render_page(
                "Проверьте почту",
                f'<p>{message}</p><p><a href="/login">Вернуться ко входу</a></p>',
            )

        token, token_hash, expires_at = (
            generate_verification_token()
        )

        async with session.begin_nested():
            await session.execute(
                delete(EmailVerificationToken).where(
                    EmailVerificationToken.user_id == user.id
                )
            )

            session.add(
                EmailVerificationToken(
                    user_id=user.id,
                    token_hash=token_hash,
                    expires_at=expires_at,
                )
            )

        await session.commit()

    verification_link = verification_url(token)

    body = (
        "Здравствуйте!\n\n"
        "Для подтверждения электронной почты "
        "перейдите по ссылке:\n\n"
        f"{verification_link}\n\n"
        "Ссылка действительна 24 часа."
    )

    try:
        await send_email(
            str(email),
            "Подтверждение электронной почты",
            body,
        )
    except Exception:
        logger.exception("Не удалось отправить письмо подтверждения")

    return render_page(
        "Проверьте почту",
        f'<p>{message}</p><p><a href="/login">Вернуться ко входу</a></p>',
    )

@app.get("/register", response_class=HTMLResponse)
def show_register():
    return render_page("Создать аккаунт", """
    <p class="intro">Зарегистрируйтесь, чтобы получить доступ к личному кабинету.</p>
    <form method="post" action="/register">
        <p>
            <label>
                Электронная почта
                <input type="email" name="email" autocomplete="email"
                       placeholder="name@example.com" required>
            </label>
        </p>
        <p>
            <label>
                Пароль
                <input type="password" name="password" autocomplete="new-password"
                       aria-describedby="password-hint" required>
            </label>
            <span class="hint" id="password-hint">От 8 символов, хотя бы одна буква и цифра.</span>
        </p>
        <p>
            <label>
                Повторите пароль
                <input type="password" name="password_check"
                       autocomplete="new-password" required>
            </label>
        </p>
        <button type="submit">Зарегистрироваться</button>
    </form>
    <p class="form-links">Уже есть аккаунт? <a href="/login">Войти</a></p>
    """)

@app.post("/register", response_class=HTMLResponse)
async def register(
    email: EmailStr = Form(),
    password: str = Form(),
    password_check: str = Form(),
):
    if password != password_check:
        return render_page(
            "Регистрация",
            '<p>Пароли не совпадают.</p>'
            '<p><a href="/register">Вернуться к регистрации</a></p>',
            status_code=400,
        )

    if len(password) < 8:
        return render_page(
            "Регистрация",
            '<p>Пароль должен содержать не менее 8 символов.</p>'
            '<p><a href="/register">Вернуться к регистрации</a></p>',
            status_code=400,
        )

    has_letter = any(char.isalpha() for char in password)
    has_digit = any(char.isdigit() for char in password)

    if not has_letter or not has_digit:
        return render_page(
            "Регистрация",
            '<p>Пароль должен содержать букву и цифру.</p>'
            '<p><a href="/register">Вернуться к регистрации</a></p>',
            status_code=400,
        )

    password_hash = await run_in_threadpool(
        password_hasher.hash, password
    )

    statement = (
        insert(User)
        .values(
            email=str(email),
            password_hash=password_hash,
        )
        .on_conflict_do_nothing(index_elements=[User.email])
        .returning(User.id)
    )

    
    token, token_hash, expires_at = generate_verification_token()

    async with Session.begin() as session:
        user_id = await session.scalar(statement)

        if user_id is not None:
            session.add(
                EmailVerificationToken(
                    user_id=user_id,
                    token_hash=token_hash,
                    expires_at=expires_at,
                )
            )

    
    if user_id is None:
        return render_page(
            "Регистрация",
            '<p>Этот адрес уже зарегистрирован.</p>'
            '<p><a href="/register">Вернуться к регистрации</a></p>',
            status_code=400,
        )

    verification_link = verification_url(token)

    subject = "Подтверждение электронной почты"

    body = (
        "Здравствуйте!\n\n"
        "Для подтверждения электронной почты "
        "перейдите по ссылке:\n\n"
        f"{verification_link}\n\n"
        "Ссылка действительна 24 часа."
    )

    await send_email(str(email), subject, body)

    return RedirectResponse(url="/login", status_code=303)

@app.get("/verify-email", response_class=HTMLResponse)
async def verify_email(token: str):
    token_hash = hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()

    async with Session.begin() as session:
        verification = await session.scalar(
            select(EmailVerificationToken).where(
                EmailVerificationToken.token_hash == token_hash
            ).with_for_update()
        )

        if verification is None:
            return render_page(
                "Подтверждение почты",
                '<p>Ссылка недействительна или уже использована.</p>'
                '<form method="get" action="/resend-verification">'
                '<button type="submit">Отправить письмо повторно</button>'
                '</form>',
                status_code=400,
            )

        if verification.expires_at <= datetime.now(timezone.utc):
            await session.delete(verification)
            return render_page(
                "Подтверждение почты",
                '<p>Срок действия ссылки истёк. Запросите новое письмо.</p>'
                '<form method="get" action="/resend-verification">'
                '<button type="submit">Отправить письмо повторно</button>'
                '</form>',
                status_code=400,
            )

        user = await session.get(User, verification.user_id)

        if user is None:
            return render_page(
                "Подтверждение почты",
                "Пользователь не найден.",
                status_code=400,
            )

        user.email_verified = True

        await session.execute(
            delete(EmailVerificationToken).where(
                EmailVerificationToken.user_id == user.id
            )
        )

    return render_page(
        "Подтверждение почты",
        '<p class="success-message">Электронная почта подтверждена!</p>'
        '<p><a href="/login">Перейти ко входу</a></p>'
    )

if __name__ == "__main__":
    uvicorn.run(app, host=APP_HOST, port=APP_PORT)
