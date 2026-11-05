# INTENTIONALLY VULNERABLE - FOR SCANNER BENCHMARKING ONLY - NEVER DEPLOY

This directory is test data for the `secaudit` benchmark. It contains **deliberately planted
vulnerabilities**, known-safe look-alikes, fake credentials, and inert prompt-injection strings.
Nothing here is a real credential. Do not run, deploy, or copy any of this code.

# shop-api

A small FastAPI storefront backend: catalog, orders with store credit, customer accounts, and
merchant and partner integrations.

## Layout

- `shop/main.py` - application object and router wiring
- `shop/auth.py` - customer tokens, partner tokens, password hashing
- `shop/routers/` - one module per API area
- `deploy/prod.env` - environment file read by the process supervisor
- `tests/` - unit tests
