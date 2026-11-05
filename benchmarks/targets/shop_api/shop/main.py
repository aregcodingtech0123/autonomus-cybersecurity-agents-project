"""Application object and router wiring."""

from fastapi import FastAPI

from shop.routers import catalog, orders, users, webhooks
from shop.settings import APP_NAME

app = FastAPI(title=APP_NAME, debug=True)

app.include_router(catalog.router)
app.include_router(orders.router)
app.include_router(users.router)
app.include_router(webhooks.router)


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok"}
