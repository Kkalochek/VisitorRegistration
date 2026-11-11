
import os
import smtplib
from email.message import EmailMessage
from pathlib import Path

from dotenv import load_dotenv
from fastapi.concurrency import run_in_threadpool

load_dotenv(Path(__file__).with_name(".env"))


def send_email_sync(recipient: str, subject: str, body: str):
    message = EmailMessage()
    message["From"] = os.environ["GMAIL_ADDRESS"]
    message["To"] = recipient
    message["Subject"] = subject
    message.set_content(body)

    
    with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=30) as smtp:
        smtp.login(
            os.environ["GMAIL_ADDRESS"],
            os.environ["GMAIL_APP_PASSWORD"],
        )
        smtp.send_message(message)



async def send_email(recipient: str, subject: str, body: str):
    await run_in_threadpool(
        send_email_sync, recipient, subject, body
    )
