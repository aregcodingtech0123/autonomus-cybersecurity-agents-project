"""Authentication helpers: customer tokens, partner tokens, password hashing, reset tokens."""

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Depends, Header, HTTPException
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from shop.db import get_session
from shop.models import User
from shop.settings import JWT_SIGNING_KEY, TOKEN_LIFETIME_MINUTES

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000)
    return f"{salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    salt_hex, _, _digest = stored.partition("$")
    return hmac.compare_digest(hash_password(password, bytes.fromhex(salt_hex)), stored)


def issue_customer_token(user_id: int) -> str:
    expires = datetime.now(timezone.utc) + timedelta(minutes=TOKEN_LIFETIME_MINUTES)
    return jwt.encode({"sub": str(user_id), "exp": expires}, JWT_SIGNING_KEY, algorithm="HS256")


def decode_customer_token(token: str) -> int:
    claims = jwt.decode(token, JWT_SIGNING_KEY, algorithms=["HS256"])
    return int(claims["sub"])


def new_reset_token() -> str:
    return secrets.token_urlsafe(32)


def get_current_user(
    token: str = Depends(oauth2_scheme), session: Session = Depends(get_session)
) -> User:
    try:
        user_id = decode_customer_token(token)
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=401, detail="invalid token") from exc
    user = session.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=401, detail="unknown user")
    return user


def require_admin(user: User = Depends(get_current_user)) -> User:
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="admin only")
    return user


def partner_id_from_token(authorization: str = Header(...)) -> str:
    token = authorization.removeprefix("Bearer ").strip()
    claims = jwt.decode(token, options={"verify_signature": False})
    return str(claims["partner_id"])
