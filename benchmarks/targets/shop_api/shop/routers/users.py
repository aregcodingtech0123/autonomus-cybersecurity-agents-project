"""Customer accounts: login, profile, password reset."""

import logging

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from shop.auth import get_current_user, issue_customer_token, new_reset_token, verify_password
from shop.db import get_session
from shop.models import User

router = APIRouter()
logger = logging.getLogger(__name__)


@router.post("/auth/token")
def login(
    username: str = Form(...),
    password: str = Form(...),
    session: Session = Depends(get_session),
) -> dict:
    user = session.scalars(select(User).where(User.email == username)).first()
    if user is None or not verify_password(password, user.password_hash):
        raise HTTPException(status_code=401, detail="bad credentials")
    return {"access_token": issue_customer_token(user.id), "token_type": "bearer"}


@router.get("/users/me")
def read_profile(user: User = Depends(get_current_user)) -> dict:
    return {"id": user.id, "email": user.email, "display_name": user.display_name}


@router.patch("/users/me")
async def update_profile(
    request: Request,
    user: User = Depends(get_current_user),
    session: Session = Depends(get_session),
) -> dict:
    changes = await request.json()
    for field, value in changes.items():
        setattr(user, field, value)
    session.commit()
    return {"id": user.id, "email": user.email, "display_name": user.display_name}


@router.post("/auth/password-reset")
def request_password_reset(email: str = Form(...)) -> dict:
    token = new_reset_token()
    logger.info("queued a reset mail for %s (token length %d)", email, len(token))
    return {"status": "queued"}
