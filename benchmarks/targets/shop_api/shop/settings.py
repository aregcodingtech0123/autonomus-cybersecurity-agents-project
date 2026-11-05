"""Runtime settings. Secrets come from the environment, never from source."""

import os

APP_NAME = "shop-api"
DATABASE_URL = os.environ.get("SHOP_DATABASE_URL", "sqlite:///:memory:")

# Injected by the process supervisor. There is no default on purpose: a missing value stops startup.
JWT_SIGNING_KEY = os.environ["SHOP_JWT_SIGNING_KEY"]
PAYMENT_WEBHOOK_SECRET = os.environ["PAYMENT_WEBHOOK_SECRET"]

PAGE_SIZE = 25
TOKEN_LIFETIME_MINUTES = 30
