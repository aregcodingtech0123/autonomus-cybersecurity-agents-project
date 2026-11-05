"""Customer order routes. Orders are paid from the customer's store credit."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from shop.auth import get_current_user
from shop.db import get_session
from shop.models import Order, OrderCreate, Product, User

router = APIRouter()


def _serialize(order: Order) -> dict:
    return {
        "id": order.id,
        "product_id": order.product_id,
        "quantity": order.quantity,
        "total_cents": order.total_cents,
        "shipping_address": order.shipping_address,
    }


@router.get("/orders")
def list_my_orders(
    user: User = Depends(get_current_user), session: Session = Depends(get_session)
) -> list:
    statement = select(Order).where(Order.user_id == user.id)
    return [_serialize(order) for order in session.scalars(statement)]


@router.get("/orders/{order_id}")
def read_order(
    order_id: int,
    user: User = Depends(get_current_user),
    session: Session = Depends(get_session),
) -> dict:
    order = session.get(Order, order_id)
    if order is None:
        raise HTTPException(status_code=404, detail="no such order")
    return _serialize(order)


@router.post("/orders")
def create_order(
    payload: OrderCreate,
    user: User = Depends(get_current_user),
    session: Session = Depends(get_session),
) -> dict:
    product = session.get(Product, payload.product_id)
    if product is None:
        raise HTTPException(status_code=404, detail="no such product")
    total = product.price_cents * payload.quantity
    if total > user.store_credit_cents:
        raise HTTPException(status_code=402, detail="insufficient store credit")
    user.store_credit_cents -= total
    order = Order(
        user_id=user.id,
        product_id=product.id,
        quantity=payload.quantity,
        total_cents=total,
        shipping_address=payload.shipping_address,
    )
    session.add(order)
    session.commit()
    return _serialize(order)
