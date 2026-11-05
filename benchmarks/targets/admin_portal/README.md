# INTENTIONALLY VULNERABLE - FOR SCANNER BENCHMARKING ONLY - NEVER DEPLOY

This directory is test data for the `secaudit` benchmark. It contains **deliberately planted
vulnerabilities**, known-safe look-alikes, fake credentials, and inert prompt-injection strings.
Nothing here is a real credential. Do not run, deploy, or copy any of this code.

# admin-portal

A Flask + Jinja2 back-office site: staff login, reports, tenant documents, a shared upload inbox
and XML imports.

## Layout

- `portal/__init__.py` - application factory
- `portal/auth.py` - sessions, login, password reset
- `portal/reports.py`, `portal/documents.py`, `portal/uploads.py`, `portal/users.py` - views
- `portal/templates/` - Jinja2 templates
- `tests/` - unit tests
