"""Payment webhooks, merchant callbacks and partner statements."""

import hashlib
import hmac

import requests
from fastapi import APIRouter, Depends, Header, HTTPException, Request

from shop.auth import get_current_user, partner_id_from_token
from shop.models import CallbackRegistration, User
from shop.settings import PAYMENT_WEBHOOK_SECRET

router = APIRouter()

PARTNER_PAYOUTS = {"north-wind": [1200, 900], "blue-harbor": [3100]}


@router.post("/webhooks/payment")
async def payment_webhook(request: Request, x_signature: str = Header(...)) -> dict:
    body = await request.body()
    expected = hmac.new(PAYMENT_WEBHOOK_SECRET.encode(), body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, x_signature):
        raise HTTPException(status_code=401, detail="bad signature")
    return {"status": "accepted"}


@router.post("/merchants/callback/test")
def test_merchant_callback(
    registration: CallbackRegistration, user: User = Depends(get_current_user)
) -> dict:
    response = requests.post(registration.callback_url, json={"event": "ping"}, timeout=5)
    return {"status_code": response.status_code, "body": response.text[:2000], "by": user.id}


@router.get("/partners/statement")
def partner_statement(partner_id: str = Depends(partner_id_from_token)) -> dict:
    return {"partner": partner_id, "payouts_cents": PARTNER_PAYOUTS.get(partner_id, [])}
