# DepScan — Dependency Health Verification for AI Skills

**Zero human interaction. Scan dependencies before install. Protect your agent.**

DepScan is an autonomous dependency health verification service built for the AI agent economy. It scans the external endpoints that an OpenClaw/ClawHub skill depends on — checking uptime, SSL validity, domain reputation, abuse reports, and blacklists — before your agent installs it.

## The Problem

A skill is only as trustworthy as the external services it calls. A skill that looks safe on the surface may connect to:
- Domains registered last week with no reputation history
- Servers with expired or invalid SSL certificates
- IPs flagged on abuse databases or DNS blacklists
- Endpoints that are already down

One compromised or unreliable dependency can break your agent's workflow, leak data, or redirect traffic to malicious infrastructure.

## How It Works

1. **Agent receives install request** → DepScan intercepts automatically
2. **Scans all external endpoints** the skill declares (uptime, SSL, WHOIS, blacklists)
3. **Makes autonomous decision**: SAFE → install / REVIEW (minor issues) → install with log / DO_NOT_INSTALL → block
4. **Upgrades automatically** if credits are exhausted (new checkout URL returned in 402 response)

No human in the loop. Ever.

## Installation

```bash
npx clawhub@latest install depscan
```

## Getting an API Key

No pre-registration required. On first use, the skill auto-creates a checkout session:

```
POST https://depscan.net/v1/billing/checkout
{"tier": "single_starter"}
→ {"checkout_url": "https://checkout.stripe.com/...", "api_key": "dsk_live_..."}
```

Complete payment once. The key is pre-generated and activates automatically via webhook.

## Pricing

| Tier | Credits | Price | Type |
|------|---------|-------|------|
| single_starter | 25 | one-time | Pay once |
| single_pro | 100 | one-time | Pay once |
| single_business | 500 | one-time | Pay once |
| deep_starter | 10 | one-time | Pay once |
| deep_pro | 50 | one-time | Pay once |
| deep_business | 200 | one-time | Pay once |
| monitor | 500/month | $9.99/month | Subscription |
| unlimited | Unlimited | $49/month | Subscription |

Each scan costs 1 credit. Results cached 24h — rescanning the same domain within 24h costs zero credits.

## Decision Rules

| Score | Recommendation | Action |
|-------|---------------|--------|
| 80–100 | SAFE_TO_INSTALL | Install immediately |
| 50–79 | REVIEW_BEFORE_INSTALL | Install only if no critical flags |
| 0–49 | DO_NOT_INSTALL | Block + log threats |

## Scan Types

| Type | Checks |
|------|--------|
| `single` | Uptime, SSL, Spamhaus blacklist |
| `deep` | Single + WHOIS, domain age, AbuseIPDB, redirect chain |

## API

```
POST /v1/billing/checkout  → create session + pre-generate API key
POST /v1/scan-deps         → scan skill dependencies
GET  /v1/scan/{scan_id}    → retrieve previous scan result
GET  /v1/health            → health check (no auth)
```

Base URL: `https://depscan.net`
Auth: `Authorization: Bearer dsk_live_...`
