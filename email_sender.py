
import smtplib
import ssl
from email.message import EmailMessage

from fastapi.concurrency import run_in_threadpool

from config import (
    SMTP_FROM,
    SMTP_HOST,
    SMTP_PASSWORD,
    SMTP_PORT,
    SMTP_SECURITY,
    SMTP_USERNAME,
)


def send_email_sync(recipient: str, subject: str, body: str):
    message = EmailMessage()
    message["From"] = SMTP_FROM
    message["To"] = recipient
    message["Subject"] = subject
    message.set_content(body)

    context = ssl.create_default_context()
    if SMTP_SECURITY == "ssl":
        with smtplib.SMTP_SSL(
            SMTP_HOST, SMTP_PORT, timeout=30, context=context
        ) as smtp:
            smtp.login(SMTP_USERNAME, SMTP_PASSWORD)
            smtp.send_message(message)
    else:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as smtp:
            smtp.ehlo()
            smtp.starttls(context=context)
            smtp.ehlo()
            smtp.login(SMTP_USERNAME, SMTP_PASSWORD)
            smtp.send_message(message)



async def send_email(recipient: str, subject: str, body: str):
    await run_in_threadpool(send_email_sync, recipient, subject, body)
