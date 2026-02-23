# DepScan API

Dependency health checking for AI agent skills. Given a list of external endpoints,
returns uptime, SSL validity, blacklist status, and a trust score (0-100).

## Quick Start

```bash
# Clone and set up
git clone https://github.com/usuario/depscan-api.git /opt/depscan-api
cd /opt/depscan-api

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Configure
cp .env.example .env
# Edit .env with real values

# Create PostgreSQL database
createdb depscan

# Start (tables created automatically on first run)
uvicorn main:app --host 0.0.0.0 --port 8001
```

## Endpoints (Fase 0)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/v1/health` | None | Health check |
| `GET` | `/docs` | None | Swagger UI |
| `POST` | `/v1/scan-deps` | Bearer token | Run dependency scan |
| `POST` | `/v1/billing/checkout` | None | Create Stripe checkout |
| `POST` | `/v1/webhook/stripe` | Stripe signature | Stripe event handler |

## Authentication

All scan endpoints require an API key in the `Authorization` header:

```
Authorization: Bearer dsk_live_xxxxxxxxxxxxxxxx
```

To get a key: call `POST /v1/billing/checkout` → complete Stripe payment → key activates.

For testing, create a key directly (requires `X-Admin-Secret` header matching `SECRET_KEY` in `.env`):

```bash
curl -X POST http://localhost:8001/v1/admin/create-key \
  -H "X-Admin-Secret: your_secret_key" \
  -G --data-urlencode "tier=single" --data-urlencode "credits=100"
```

## Scan Request

```bash
curl -X POST https://depscan.net/v1/scan-deps \
  -H "Authorization: Bearer dsk_live_xxx" \
  -H "Content-Type: application/json" \
  -d '{
    "endpoints": [
      "https://api.openai.com",
      "https://api.anthropic.com"
    ],
    "scan_type": "single"
  }'
```

## Score Interpretation

| Score | Status | Recommendation |
|-------|--------|----------------|
| 80-100 | SAFE | SAFE_TO_INSTALL |
| 60-79 | CAUTION | REVIEW_BEFORE_INSTALL |
| 40-59 | RISK | REVIEW_BEFORE_INSTALL |
| 0-39 | CRITICAL | DO_NOT_INSTALL |

## Deploy (Contabo VPS)

```bash
# Install systemd service
cp deploy/depscan.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable depscan
systemctl start depscan

# Verify
curl http://localhost:8001/v1/health
```

## Running Tests

```bash
pip install -r requirements.txt
pytest tests/ -v
```

## Roadmap

- **Fase 0** (current): Uptime + SSL + Spamhaus DBL blacklist
- **Fase 1**: Deep scan — WHOIS domain age + AbuseIPDB
- **Fase 2**: Monitor tier — scheduled re-scans + webhook alerts
- **Fase 3**: SecurityScan integration bundle
