
import hashlib
import secrets
from datetime import datetime, timedelta, timezone


def generate_verification_token():
    token = secrets.token_urlsafe(32)

    token_hash = hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()

    expires_at = datetime.now(timezone.utc) + timedelta(
        hours=24
    )

    return token, token_hash, expires_at
