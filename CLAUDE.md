# CLAUDE.md — DepScan API
> Documento maestro para Claude Code. Lee este archivo completo antes de generar cualquier código.

---

## 1. Identidad del Proyecto

**Nombre:** DepScan API  
**Dominio:** depscan.net  
**Propósito:** Servicio de dependency health checking para skills de agentes IA. Dado un skill o lista de endpoints externos, retorna un reporte de salud: uptime, reputación de dominio, validez de certificados SSL, listas negras de abuse y score de confianza global.  
**Mercado objetivo:** Agentes IA (AI-to-AI). El cliente que consume la API es un agente, no un humano.  
**Relación con SecurityScan API:** Proyecto hermano e independiente. Mismo servidor VPS (Contabo), puerto diferente. En Fase 3 se integrarán para ofrecer bundle, pero el código debe mantenerse desacoplado.

---

## 2. Principios de Diseño — NO Negociables

1. **Autonomía total.** El servicio opera sin intervención humana. No hay paneles de administración manual, no hay aprobaciones. Todo es automático.
2. **Máxima reutilización de infraestructura.** El servidor ya existe. No proponer soluciones que requieran recursos adicionales no justificados.
3. **Desacoplado de SecurityScan.** Repositorio Git separado, proceso systemd separado, base de datos separada. Comparten servidor, no código.
4. **AI-to-AI first.** Los endpoints y respuestas JSON están diseñados para ser consumidos por agentes IA, no por interfaces humanas. Claridad semántica en los campos, no UX para humanos.
5. **Fail safe conservador.** Si hay duda sobre la seguridad de un endpoint, el score es neutro (50), nunca se marca como inseguro sin evidencia concreta. Falsos negativos son preferibles a falsos positivos.
6. **Sin over-engineering.** MVP primero. No implementar lo que no está en la Fase actual del roadmap.

---

## 3. Stack Técnico

| Componente | Tecnología |
|---|---|
| Lenguaje | Python 3.11+ |
| Framework | FastAPI |
| Servidor ASGI | Uvicorn |
| HTTP client | httpx (async) |
| SSL validation | Python stdlib `ssl` + `certifi` |
| Base de datos | PostgreSQL (via asyncpg o SQLAlchemy async) |
| Cache | Redis (TTL 24h para resultados de dominio) |
| Job scheduler | APScheduler (para tier Monitor) |
| Pagos | Stripe Python SDK |
| Process manager | systemd (servicio independiente) |
| Puerto | 8001 (8000 reservado para SecurityScan) |
| Variables de entorno | python-dotenv, archivo `.env` nunca commiteado |

**APIs de datos externos:**
| Fuente | Uso | Tier |
|---|---|---|
| AbuseIPDB | Abuse score por IP | Free (1000/día) |
| Spamhaus DBL | Domain blacklist | Feed público |
| WHOIS API (whoapi.com) | Historial de propietario, edad del dominio | $10/mes plan básico |
| Claude API (Anthropic) | Análisis semántico de schema drift | Solo casos complejos, Fase 2+ |

---

## 4. Estructura de Directorios

```
depscan-api/
├── CLAUDE.md                  # Este archivo
├── README.md
├── .env.example               # Template sin valores reales
├── .gitignore
├── requirements.txt
├── main.py                    # Entry point FastAPI app
├── app/
│   ├── __init__.py
│   ├── config.py              # Settings via pydantic-settings
│   ├── database.py            # Async DB connection
│   ├── models/
│   │   ├── __init__.py
│   │   ├── scan.py            # Pydantic models request/response
│   │   └── db.py              # SQLAlchemy ORM models
│   ├── routers/
│   │   ├── __init__.py
│   │   ├── scan.py            # POST /v1/scan-deps
│   │   ├── monitor.py         # GET /v1/monitor/{skill_id}/history
│   │   └── billing.py         # POST /v1/webhook/stripe
│   ├── services/
│   │   ├── __init__.py
│   │   ├── extractor.py       # Extrae URLs desde skill manifest
│   │   ├── checker.py         # Orquesta todos los checks en paralelo
│   │   ├── uptime.py          # httpx uptime + latencia
│   │   ├── ssl_check.py       # Validación certificado SSL
│   │   ├── domain_rep.py      # WHOIS + edad de dominio
│   │   ├── blacklist.py       # AbuseIPDB + Spamhaus
│   │   └── scorer.py          # Algoritmo de score 0-100
│   ├── middleware/
│   │   ├── __init__.py
│   │   └── rate_limit.py      # Rate limiting por API key via Redis
│   └── tasks/
│       ├── __init__.py
│       └── monitor_job.py     # APScheduler job para tier Monitor
├── migrations/                # Alembic migrations
├── tests/
│   ├── __init__.py
│   ├── test_checker.py
│   ├── test_scorer.py
│   └── test_api.py
└── deploy/
    └── depscan.service        # systemd unit file
```

---

## 5. Modelos de Datos

### 5.1 Request — POST /v1/scan-deps

```python
class ScanRequest(BaseModel):
    skill_url: Optional[str] = None          # URL del skill manifest
    endpoints: Optional[List[str]] = None    # Lista directa de endpoints
    scan_type: Literal["single", "deep"] = "single"
    callback_url: Optional[str] = None       # Webhook para resultado async

    @validator("endpoints", always=True)
    def must_have_source(cls, v, values):
        if not v and not values.get("skill_url"):
            raise ValueError("Se requiere skill_url o endpoints")
        return v
```

### 5.2 Response — Scan Result

```python
class EndpointResult(BaseModel):
    url: str
    status: Literal["UP", "DOWN", "TIMEOUT", "SSL_ERROR", "UNKNOWN"]
    latency_ms: Optional[int]
    ssl_expires_days: Optional[int]          # None si no es HTTPS
    ssl_valid: Optional[bool]
    domain_age_days: Optional[int]           # None si WHOIS falla
    domain_owner_changed: Optional[bool]     # None si no hay historial
    abuse_score: int                         # 0-100, AbuseIPDB
    in_blacklist: bool                       # Spamhaus DBL
    flags: List[str]                         # NEW_DOMAIN, SSL_EXPIRING, etc.
    score: int                               # 0-100

class ScanResponse(BaseModel):
    scan_id: str
    skill: Optional[str]
    overall_score: int
    status: Literal["SAFE", "CAUTION", "RISK", "CRITICAL"]
    endpoints: List[EndpointResult]
    recommendation: Literal["SAFE_TO_INSTALL", "REVIEW_BEFORE_INSTALL", "DO_NOT_INSTALL"]
    scan_type: str
    timestamp: datetime
    processing_time_ms: int
```

### 5.3 Flags disponibles

| Flag | Condición |
|---|---|
| `NEW_DOMAIN` | domain_age_days < 90 |
| `SSL_EXPIRING` | ssl_expires_days < 30 |
| `SSL_EXPIRED` | ssl_expires_days <= 0 |
| `HIGH_LATENCY` | latency_ms > 2000 |
| `ABUSE_REPORTED` | abuse_score > 25 |
| `IN_BLACKLIST` | in_blacklist == True |
| `OWNER_CHANGED` | domain_owner_changed == True |
| `REDIRECT_CHAIN` | más de 2 redirects detectados |
| `NO_HTTPS` | esquema http:// en endpoint |

---

## 6. Algoritmo de Score

El score de cada endpoint es 0-100. El overall_score es el promedio ponderado (endpoints con más flags pesan más hacia abajo).

```python
def calculate_endpoint_score(result: EndpointResult) -> int:
    score = 100

    # Penalizaciones por status
    if result.status == "DOWN":       score -= 60
    if result.status == "TIMEOUT":    score -= 40
    if result.status == "SSL_ERROR":  score -= 50
    if result.status == "UNKNOWN":    score -= 20

    # Penalizaciones por SSL
    if result.ssl_expires_days is not None:
        if result.ssl_expires_days <= 0:    score -= 40
        elif result.ssl_expires_days < 14:  score -= 25
        elif result.ssl_expires_days < 30:  score -= 10

    # Penalizaciones por dominio
    if result.domain_age_days is not None and result.domain_age_days < 30:   score -= 35
    elif result.domain_age_days is not None and result.domain_age_days < 90: score -= 15

    if result.domain_owner_changed:   score -= 30

    # Penalizaciones por abuse
    if result.abuse_score > 75:       score -= 40
    elif result.abuse_score > 50:     score -= 25
    elif result.abuse_score > 25:     score -= 10

    if result.in_blacklist:           score -= 45
    if "NO_HTTPS" in result.flags:    score -= 15
    if "REDIRECT_CHAIN" in result.flags: score -= 10

    return max(0, min(100, score))

def overall_status(score: int) -> str:
    if score >= 80:   return "SAFE"
    if score >= 60:   return "CAUTION"
    if score >= 40:   return "RISK"
    return "CRITICAL"

def recommendation(score: int) -> str:
    if score >= 80:   return "SAFE_TO_INSTALL"
    if score >= 50:   return "REVIEW_BEFORE_INSTALL"
    return "DO_NOT_INSTALL"
```

---

## 7. Pricing y API Keys

### 7.1 Tiers

| Tier | Precio | Límite |
|---|---|---|
| `single` | $0.05 / scan | Uptime + SSL + blacklist básico |
| `deep` | $0.15 / scan | Single + WHOIS + AbuseIPDB + redirect chain |
| `monitor` | $5.00 / skill / mes | Deep scan inicial + re-scan cada 6h + webhook alerts |
| `unlimited` | $49.00 / mes | Single + Deep ilimitados (sin Monitor) |

### 7.2 API Key

Cada cliente tiene una API key tipo `dsk_live_xxxxxxxxxxxx` (prefijo `dsk_`). Se envía en header:

```
Authorization: Bearer dsk_live_xxxxxxxxxxxx
```

La tabla `api_keys` en PostgreSQL almacena: `key_hash`, `tier`, `credits_remaining`, `stripe_customer_id`, `created_at`, `last_used_at`.

### 7.3 Rate limiting

- `single`/`deep`: 60 requests/minuto por API key
- `unlimited`: 300 requests/minuto
- `monitor`: sin rate limit (job interno)

---

## 8. Endpoints de la API

### `POST /v1/scan-deps`
Scan bajo demanda. Responde síncronamente si hay ≤ 10 endpoints, asíncronamente (con `callback_url`) si hay más.

### `GET /v1/scan/{scan_id}`
Recupera resultado de un scan previo por ID.

### `POST /v1/monitor/subscribe`
Suscribe un skill al tier Monitor. Requiere API key con tier `monitor` activo en Stripe.

### `DELETE /v1/monitor/{skill_id}`
Cancela suscripción Monitor.

### `GET /v1/monitor/{skill_id}/history`
Retorna historial de scans del skill (últimos 30 días).

### `POST /v1/webhook/stripe`
Recibe eventos de Stripe: `checkout.session.completed`, `invoice.payment_failed`, `customer.subscription.deleted`.

### `GET /v1/health`
Health check público. Retorna `{"status": "ok", "version": "x.x.x"}`.

### `GET /docs`
Swagger UI autogenerado por FastAPI. Público, sin autenticación.

---

## 9. Variables de Entorno (.env.example)

```env
# App
APP_ENV=production
APP_PORT=8001
SECRET_KEY=

# Database
DATABASE_URL=postgresql+asyncpg://user:pass@localhost/depscan

# Redis
REDIS_URL=redis://localhost:6379/1

# Stripe
STRIPE_SECRET_KEY=
STRIPE_WEBHOOK_SECRET=
STRIPE_PRICE_SINGLE=price_xxx
STRIPE_PRICE_DEEP=price_xxx
STRIPE_PRICE_MONITOR=price_xxx
STRIPE_PRICE_UNLIMITED=price_xxx

# External APIs
ABUSEIPDB_API_KEY=
WHOIS_API_KEY=
ANTHROPIC_API_KEY=

# Monitoring alerts
ALERT_SCORE_DROP_THRESHOLD=20
MONITOR_SCAN_INTERVAL_HOURS=6
```

---

## 10. Roadmap de Fases — Qué implementar en cada fase

### Fase 0 — MVP (implementar primero)
- [ ] Estructura de directorios completa
- [ ] FastAPI app con `POST /v1/scan-deps` (scan_type: "single" únicamente)
- [ ] `uptime.py` — httpx async, timeout 10s, detecta redirects
- [ ] `ssl_check.py` — extrae expiración y validez del cert
- [ ] `blacklist.py` — solo Spamhaus DBL feed (AbuseIPDB en Fase 1)
- [ ] `scorer.py` — algoritmo completo desde el inicio
- [ ] `extractor.py` — parser básico: acepta lista directa de URLs
- [ ] PostgreSQL: tablas `api_keys`, `scans`, `endpoint_results`
- [ ] Redis: cache de resultados por dominio (TTL 1h Fase 0)
- [ ] Stripe: productos y checkout para `single` y `deep`
- [ ] `GET /v1/health` y `GET /docs`
- [ ] systemd unit file
- [ ] `.env.example` completo
- [ ] `README.md` con instrucciones de deploy

### Fase 1 — Deep Scan completo
- [ ] `domain_rep.py` — WHOIS API integration (whoapi.com)
- [ ] `blacklist.py` — agregar AbuseIPDB
- [ ] `extractor.py` — parser de skill manifests YAML/JSON
- [ ] Cache TTL upgrade a 24h para resultados de dominio
- [ ] `POST /v1/scan-deps` soporta scan_type: "deep"
- [ ] `GET /v1/scan/{scan_id}` endpoint

### Fase 2 — Monitor continuo ✅ COMPLETA
- [x] `monitor_job.py` — APScheduler, re-scan cada 6h, distributed Redis lock
- [x] Sistema de alertas: webhook callback cuando score cae > threshold
- [x] `POST /v1/monitor/subscribe` y `DELETE /v1/monitor/{skill_id}`
- [x] `GET /v1/monitor/{skill_id}/history`
- [x] Stripe subscriptions para billing recurrente (monitor=500cr/mes, unlimited=999999cr/mes)
- [x] Tier `unlimited` con rate limit diferenciado (300 req/min)
- [x] Async scan con callback_url para > 10 endpoints (respuesta PENDING + background task)

### Fase 3 — Integración SecurityScan ✅ COMPLETA
- [x] Endpoint interno `POST /internal/scan-deps` sin auth (solo localhost, require_localhost)
- [ ] Bundle pricing en Stripe (pendiente hasta que SecurityScan lo solicite)

### Fase Final — Auditoría de Seguridad ✅ COMPLETA (2026-02-26)
- [x] Revisado: inyección SQL (ORM parametrizado), autenticación (SHA256 + hmac.compare_digest)
- [x] Revisado: manejo de secretos (env vars, nunca en logs), validación de inputs (Pydantic)
- [x] Revisado: rate limiting (Redis + in-memory fallback con prune), SSRF (múltiples capas)
- [x] Revisado: firma Stripe webhook (construct_event), admin endpoint (oculto + secret), CORS
- [x] Fix: nginx proxy_set_header tenía valores vacíos — corregido
- [x] Fix: nginx sin bloqueo de /v1/admin/ ni /internal/ — deny all añadidos
- [x] Fix: limit_req_zone sin definir en nginx — documentada (va en http{} de nginx.conf)
- [x] Fix: rate_limit.py _fallback_counts memory leak — _prune_old_buckets() implementado
- [x] Alembic configurado con migración inicial completa (alembic upgrade head)

---

## 11. Convenciones de Código

- **Type hints** en todas las funciones, sin excepción.
- **async/await** para toda operación de I/O (DB, HTTP, Redis).
- **Manejo de errores:** nunca propagar excepciones crudas al cliente. Siempre retornar JSON estructurado con `{"error": "...", "code": "..."}`.
- **Logging:** usar `structlog` o el logging estándar con formato JSON. Nunca `print()`.
- **Tests:** cada servicio tiene su test correspondiente en `tests/`. Usar `pytest` + `pytest-asyncio`.
- **Secrets:** nunca hardcodear. Siempre desde `config.py` que lee `.env`.
- **Nombres de variables:** inglés. Comentarios: pueden ser en español si el contexto es de negocio.

---

## 12. Instrucciones de Deploy (Contabo VPS)

```bash
# 1. Clonar repo
git clone https://github.com/usuario/depscan-api.git /opt/depscan-api

# 2. Crear virtualenv
python3 -m venv /opt/depscan-api/venv
source /opt/depscan-api/venv/bin/activate
pip install -r requirements.txt

# 3. Configurar .env
cp .env.example .env
# Editar .env con valores reales

# 4. Crear base de datos PostgreSQL
createdb depscan
alembic upgrade head

# 5. Instalar y arrancar servicio systemd
cp deploy/depscan.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable depscan
systemctl start depscan

# 6. Verificar
curl http://localhost:8001/v1/health
```

### systemd unit file (`deploy/depscan.service`)
```ini
[Unit]
Description=DepScan API
After=network.target postgresql.service redis.service

[Service]
Type=simple
User=www-data
WorkingDirectory=/opt/depscan-api
EnvironmentFile=/opt/depscan-api/.env
ExecStart=/opt/depscan-api/venv/bin/uvicorn main:app --host 0.0.0.0 --port 8001 --workers 2
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

---

## 13. Configuración Nginx (proxy inverso)

```nginx
server {
    listen 443 ssl;
    server_name depscan.net www.depscan.net;

    # SSL certs (Let's Encrypt via certbot)
    ssl_certificate /etc/letsencrypt/live/depscan.net/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/depscan.net/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8001;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

server {
    listen 80;
    server_name depscan.net www.depscan.net;
    return 301 https://$host$request_uri;
}
```

---

## 14. Notas para Claude Code

- **Empieza siempre por Fase 0.** No saltar a fases superiores hasta que la actual esté completa y los tests pasen.
- **El puerto 8000 está reservado** para SecurityScan API. DepScan usa 8001 siempre.
- **Redis database 1** (SecurityScan usa database 0 si existe).
- **No crear interfaz web/frontend.** Este es un servicio API puro. El único HTML que debe existir es el `/docs` de Swagger, que FastAPI genera automáticamente.
- **El scan_id** debe ser un UUID v4 prefijado: `dep_` + uuid4 sin guiones. Ejemplo: `dep_a1b2c3d4e5f6...`
- **Cuando un check externo falla** (WHOIS API caída, AbuseIPDB sin respuesta), el campo correspondiente retorna `null` y no penaliza el score. Nunca fallar el scan completo por una fuente de datos externa.
- **El campo `recommendation`** es el campo más importante para el agente consumidor. Debe ser siempre determinista dado el score.
- **Stripe webhook** debe verificar la firma antes de procesar cualquier evento. Sin verificación de firma, rechazar con 400.
