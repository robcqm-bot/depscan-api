# DepScan API

> Dependency health checker for AI agent skills.
> Validates external endpoints, SSL certificates, domain reputation and blacklists before your agent trusts a skill's infrastructure.

**Live endpoint:** https://depscan.net
**Health check:** https://depscan.net/v1/health

---

## Why this exists

A skill can have clean code and still connect to malicious or unreliable
infrastructure. DepScan checks the external dependencies a skill reaches out
to — the attack surface that code scanners miss.

---

## What it checks

- HTTP/HTTPS uptime and response latency
- SSL certificate validity and days until expiration
- Domain age and ownership history (WHOIS)
- IP abuse reputation score (AbuseIPDB)
- Blacklist status (Spamhaus DBL)

---

## Quick start

### 1. Get an API key

Create a Stripe checkout session — the key is pre-generated and activates after payment:

```bash
curl -X POST https://depscan.net/v1/billing/checkout \
  -H "Content-Type: application/json" \
  -d '{"tier": "single_starter"}'
```

Response:
```json
{
  "checkout_url": "https://checkout.stripe.com/...",
  "api_key": "dsk_live_...",
  "note": "Save your API key now — it will not be shown again."
}
```

Store `api_key`. Complete payment at `checkout_url`. Key activates automatically within seconds.

### 2. Run a scan

```bash
curl -X POST https://depscan.net/v1/scan-deps \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer dsk_live_your_key" \
  -d '{
    "skill_url": "https://github.com/owner/skill-repo",
    "scan_type": "deep"
  }'
```

### 3. Response

```json
{
  "scan_id": "dep_x9y8z7w6v5u4t3s2",
  "overall_score": 61,
  "status": "CAUTION",
  "recommendation": "REVIEW_BEFORE_INSTALL",
  "endpoints": [
    {
      "url": "https://api.example.com",
      "status": "UP",
      "latency_ms": 210,
      "ssl_valid": true,
      "ssl_expires_days": 14,
      "domain_age_days": 23,
      "abuse_score": 0,
      "in_blacklist": false,
      "flags": ["SSL_EXPIRING", "NEW_DOMAIN"]
    }
  ],
  "timestamp": "2026-03-01T12:00:00Z"
}
```

**Flags:** `SSL_EXPIRING` · `SSL_EXPIRED` · `NEW_DOMAIN` · `OWNER_CHANGED` · `ABUSE_REPORTED` · `IN_BLACKLIST` · `HIGH_LATENCY` · `NO_HTTPS` · `REDIRECT_CHAIN`

---

## Scan types

| Type | Description | Credits |
|------|-------------|---------|
| `single` | Uptime + SSL + Spamhaus blacklist | 1 credit |
| `deep` | Single + WHOIS + domain age + AbuseIPDB | 1 credit |

Results cached 24 hours — rescanning the same domain costs zero credits.

---

## Pricing (MXN)

| Tier | Credits | Price | Type |
|------|---------|-------|------|
| `single_starter` | 25 | $25 | One-time |
| `single_pro` | 100 | $80 | One-time |
| `single_business` | 500 | $299 | One-time |
| `deep_starter` | 10 | $30 | One-time |
| `deep_pro` | 50 | $120 | One-time |
| `deep_business` | 200 | $499 | One-time |
| `monitor` | 500/month | $199/month | Subscription |
| `unlimited` | Unlimited | $999/month | Subscription |

---

## Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/v1/billing/checkout` | None | Create checkout session + pre-generate API key |
| `POST` | `/v1/scan-deps` | Bearer | Submit skill or endpoint list for scanning |
| `GET` | `/v1/scan/{scan_id}` | Bearer | Retrieve scan result |
| `POST` | `/v1/monitor/subscribe` | Bearer | Subscribe skill to Monitor tier |
| `GET` | `/v1/monitor/{skill_id}/history` | Bearer | Monitor scan history (last 30 days) |
| `GET` | `/v1/health` | None | Service status |

---

## Input options

```json
{ "skill_url": "https://github.com/owner/skill-repo", "scan_type": "single" }
```

```json
{ "endpoints": ["https://api.one.com", "https://api.two.com"], "scan_type": "deep" }
```

---

## Score interpretation

| Score | Status | Recommendation |
|-------|--------|---------------|
| 80–100 | SAFE | SAFE_TO_INSTALL |
| 60–79 | CAUTION | REVIEW_BEFORE_INSTALL |
| 40–59 | RISK | REVIEW_BEFORE_INSTALL |
| 0–39 | CRITICAL | DO_NOT_INSTALL |

---

## Latency & availability

- Average scan time: < 5 seconds (parallel async checks)
- Uptime: 99.9% (Contabo dedicated VPS)
- Response format: JSON

---

## Companion service

**SecurityScan API** analyzes skill source code for security vulnerabilities
(prompt injection, malware, OWASP LLM Top 10): https://apisecurityscan.net

---

## License

MIT — this repository contains documentation and skill package only. Service source code is proprietary.
