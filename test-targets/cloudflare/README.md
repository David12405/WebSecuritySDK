# Cloudflare Test Targets — Module 1 Reconnaissance Validation

Deterministic, controlled Cloudflare-based test targets for validating **Module 1 (Scope & Reconnaissance)** of the Web Security AI Agent, specifically the deterministic pipeline:

$$\text{Raw Tool Output} \rightarrow \text{EvidenceArtifactRecord} \rightarrow \text{Deterministic Parser} \rightarrow \text{ObservationRecord} \rightarrow \text{Observation Validator} \rightarrow \text{Validated Observation Store} \rightarrow \text{Normalization} \rightarrow \text{EndpointDefinition} \rightarrow \text{TargetModel}$$

---

> [!CAUTION]
> **Reconnaissance Testing Only — Not Vulnerable Applications**
>
> These Cloudflare applications are **NOT** vulnerable targets. They do **NOT** contain SQL injection, command injection, XSS, SSRF, or any other intentional exploitable vulnerabilities. All reflected inputs are strictly HTML-escaped.
>
> Their sole purpose is to serve as **deterministic ground-truth targets** for testing:
> - HTTP reconnaissance & metadata collection
> - Crawler endpoint and form discovery
> - OpenAPI 3.x specification discovery and parsing
> - Browser runtime discovery (fetch, XHR, and DOM click-triggered calls)
> - Input parameter discovery (`QUERY`, `PATH`, `FORM`, `JSON_BODY`, `HEADER`, `COOKIE`, `DOM`)
> - `TargetModel` construction and endpoint normalization

---

## 1. Architecture & Why Three Targets

The test environment consists of three independent Cloudflare Workers targets:

```
WebSecuritySDK/
└── test-targets/
    └── cloudflare/
        ├── targets/
        │   ├── basic/          # Basic HTTP/HTML application
        │   ├── api/            # REST API + OpenAPI 3.0.3 specification
        │   └── spa/            # JavaScript Single Page Application
        ├── ground-truth/
        │   ├── basic.json      # Ground truth oracle for basic
        │   ├── api.json        # Ground truth oracle for api
        │   └── spa.json        # Ground truth oracle for spa
        ├── integration-tests/  # Conformance, live HTTP, and Playwright tests
        ├── scripts/            # Development automation scripts
        ├── package.json
        ├── playwright.config.mjs
        └── README.md
```

### Why Three Separate Targets?

Isolating targets is critical for testing the deterministic pipeline:
1. **`basic-target` (Crawler / HTTP Observation)**: Classic server-rendered HTML. Links, GET/POST forms, cookies, redirects, and header reflection are discoverable by static crawlers and HTTP probes without needing browser automation or API specs.
2. **`api-target` (API Spec / REST Discovery)**: Pure JSON API with an OpenAPI 3.0.3 document. Validates that the spec parser correctly extracts operations, path parameters (`/api/users/{id}`), query parameters, nested JSON bodies (`filters.category`), and required headers (`X-Test-Client`).
3. **`spa-target` (Browser Runtime vs Static Crawler)**: Static HTML shell containing **no direct links** to API endpoints. Demonstrates that a static crawler only sees `/` and `/app.js`, while browser instrumentation (Playwright) dynamically discovers runtime `fetch` and `XMLHttpRequest` endpoints on page load, as well as button-click triggered endpoints (`/api/search`, `/api/products/{id}`, `/api/cart`).

Keeping them separate prevents cross-contamination (e.g. an API spec accidentally sitting on the SPA origin, which would hide whether browser instrumentation genuinely discovered runtime endpoints).

---

## 2. Implemented Endpoint Matrix

### 2.1 BASIC Target (`basic-target`)

| ID | Method | Path | Request Content-Type | Inputs (Location) | Discovery Source | Response |
|---|---|---|---|---|---|---|
| B1 | `GET` | `/` | — | — | `CRAWLER`, `HTTP_OBSERVATION` | 200 HTML with links and forms |
| B2 | `GET` | `/search` | — | `q` (`QUERY`) | `CRAWLER`, `HTTP_OBSERVATION` | 200 HTML (escaped query reflection) |
| B3 | `GET` | `/redirect` | — | — | `CRAWLER`, `HTTP_OBSERVATION` | 302 redirect to `/final` |
| B4 | `GET` | `/final` | — | — | `HTTP_OBSERVATION`, `CRAWLER` | 200 HTML landing page |
| B5 | `GET` | `/cookie` | — | `test_session` (`COOKIE`) | `CRAWLER`, `HTTP_OBSERVATION` | 200 JSON, sets `test_session` cookie |
| B6 | `GET` | `/headers` | — | `x-test-header` (`HEADER`) | `CRAWLER`, `HTTP_OBSERVATION` | 200 JSON with allowlisted headers |
| B7 | `POST` | `/login` | `application/x-www-form-urlencoded` | `username`, `password` (`FORM`) | `CRAWLER` | 200 HTML acknowledgement (no auth) |
| B8 | `POST` | `/form` | `application/x-www-form-urlencoded` | `full_name`, `email`, `age`, `country`, `comment`, `subscribe`, `source` (`FORM`) | `CRAWLER` | 200 JSON with sorted received field list |

*Unknown routes return deterministic `404 {"error": "not_found"}`. Invalid methods return `405` with `Allow` header.*

### 2.2 API Target (`api-target`)

| ID | Method | Path | Request Content-Type | Inputs (Location) | Discovery Source | Response |
|---|---|---|---|---|---|---|
| A1 | `GET` | `/` | — | — | `HTTP_OBSERVATION` | 200 JSON API root info |
| A2 | `GET` | `/openapi.json` | — | — | `HTTP_OBSERVATION`, `MANUAL` | 200 JSON OpenAPI 3.0.3 spec |
| A3 | `GET` | `/api/users` | — | `id` (`QUERY`, optional) | `API_SPEC`, `HTTP_OBSERVATION` | 200 JSON user list or filtered user |
| A4 | `GET` | `/api/users/{id}` | — | `id` (`PATH`, required) | `API_SPEC`, `HTTP_OBSERVATION` | 200 JSON single user (or 404) |
| A5 | `POST` | `/api/search` | `application/json` | `keyword`, `filters`, `filters.category`, `filters.minPrice` (`JSON_BODY`) | `API_SPEC`, `HTTP_OBSERVATION` | 200 JSON filtered product results |
| A6 | `POST` | `/api/orders` | `application/json` | `productId`, `quantity`, `shipping`, `shipping.city`, `shipping.country` (`JSON_BODY`) | `API_SPEC`, `HTTP_OBSERVATION` | 201 JSON order accepted (`ORD-<id>-<qty>`) |
| A7 | `GET` | `/api/client-info` | — | `X-Test-Client` (`HEADER`, required) | `API_SPEC`, `HTTP_OBSERVATION` | 200 JSON client verification status |

### 2.3 SPA Target (`spa-target`)

| ID | Method | Path | Trigger Mechanism | Inputs (Location) | Discovery Source | Static Visible? |
|---|---|---|---|---|---|---|
| S1 | `GET` | `/` | Navigation | `keyword` (`DOM`, `#search-input`) | `CRAWLER`, `HTTP_OBSERVATION`, `BROWSER` | ✅ Yes |
| S2 | `GET` | `/app.js` | `<script src>` | — | `CRAWLER`, `BROWSER` | ✅ Yes |
| S3 | `GET` | `/api/products` | Page load (`fetch`) | — | `BROWSER` | ❌ No |
| S4 | `GET` | `/api/categories` | Page load (`XMLHttpRequest`) | — | `BROWSER` | ❌ No |
| S5 | `POST` | `/api/search` | Click `#btn-search` | `keyword` (`JSON_BODY`) | `BROWSER` | ❌ No |
| S6 | `GET` | `/api/products/{id}` | Click `#btn-details-{id}` | `id` (`PATH`) | `BROWSER` | ❌ No |
| S7 | `POST` | `/api/cart` | Click `#btn-cart-{id}` | `productId`, `quantity` (`JSON_BODY`) | `BROWSER` | ❌ No |

---

## 3. Ground Truth Oracle Architecture

Ground-truth files live in `ground-truth/`:
- `ground-truth/basic.json`
- `ground-truth/api.json`
- `ground-truth/spa.json`

### Canonical Vocabulary Alignment
The ground truth strictly shares the canonical enumeration from `websecuritycheck.domain`:
- **`InputLocation`**: `QUERY`, `PATH`, `FORM`, `JSON_BODY`, `XML_BODY`, `HEADER`, `COOKIE`, `MULTIPART`, `DOM`
- **`DiscoverySource`**: `CRAWLER`, `API_SPEC`, `HTTP_OBSERVATION`, `BROWSER`, `SOURCE_CODE`, `MANUAL`, `OTHER`

### Nested JSON Representation
Nested JSON body parameters use standard dotted notation while preserving the parent object:
```json
[
  { "name": "filters", "location": "JSON_BODY", "dataType": "object" },
  { "name": "filters.category", "location": "JSON_BODY", "dataType": "string", "parent": "filters" },
  { "name": "filters.minPrice", "location": "JSON_BODY", "dataType": "number", "parent": "filters" }
]
```

### Critical Separation Principle
> [!IMPORTANT]
> **Ground Truth is Oracle Data Only**
>
> The Web Security AI Agent must **NEVER** read, import, or consult `ground-truth/*.json` during reconnaissance. Ground-truth files are test oracles consumed exclusively by integration test comparators after the agent runs.

---

## 4. Local Execution

### Prerequisites
- Node.js v20.15+ and npm
- Dependencies installed:
  ```bash
  cd test-targets/cloudflare
  npm install
  ```

### Running All Targets Locally
To start all three workers concurrently:
```bash
npm run dev:all
```
This binds:
- `basic-target` $\rightarrow$ `http://localhost:8787`
- `api-target` $\rightarrow$ `http://localhost:8788`
- `spa-target` $\rightarrow$ `http://localhost:8789`

Alternatively, run an individual target:
```bash
npm run dev:basic   # port 8787
npm run dev:api     # port 8788
npm run dev:spa     # port 8789
```

---

## 5. Cloudflare Deployment

### 1. Cloudflare Login
Login to your Cloudflare account using Wrangler:
```bash
npx wrangler login
```
Verify your authenticated account:
```bash
npx wrangler whoami
```

### 2. Deploy Each Target
Deploy independently to your Cloudflare Workers subdomain:
```bash
npm run deploy:basic
npm run deploy:api
npm run deploy:spa
```

### 3. Expected URLs
Wrangler will display the deployed URLs upon successful deploy:
- `https://basic-target.<account-subdomain>.workers.dev`
- `https://api-target.<account-subdomain>.workers.dev`
- `https://spa-target.<account-subdomain>.workers.dev`

*(No custom domain or paid Cloudflare features required.)*

---

## 6. Running Verification & Smoke Tests

### 1. Offline Ground-Truth Schema Test
Validates the structural integrity, enums, path parameters, nested parents, and probe definitions without network:
```bash
npm run test:offline
```

### 2. Full Live Test Suite (HTTP & Conformance)
With local servers running (via `npm run dev:all`):
```bash
npm test
```
This runs 74 test cases across:
- `basic.test.mjs`: HTTP status, redirects, headers, cookies, form data
- `api.test.mjs`: REST operations, query/path parameters, nested JSON payloads, custom headers
- `openapi.test.mjs`: OpenAPI 3.0.3 schema compliance and 1-to-1 parity with ground truth
- `spa.http.test.mjs`: Static HTML leak checks (verifies zero `/api/` links in initial HTML)
- `conformance.test.mjs`: Probes every ground-truth endpoint against the running server

### 3. Browser Runtime Verification (Playwright)
Executes a headless Chromium browser against the SPA to verify dynamic fetch/XHR requests and DOM click triggers:
```bash
npm run test:browser
```

### 4. Testing Against Deployed Cloudflare Workers
Point tests at your production `workers.dev` deployments:
```bash
$env:BASIC_URL="https://basic-target.<subdomain>.workers.dev"
$env:API_URL="https://api-target.<subdomain>.workers.dev"
$env:SPA_URL="https://spa-target.<subdomain>.workers.dev"

npm test
npm run test:browser
```

---

## 7. Integration with the Web Security AI Agent

In future milestones, the end-to-end integration flow will operate as follows:

```
┌─────────────────────────────────┐
│ Cloudflare Test Target          │
│ (basic, api, or spa)            │
└────────────────┬────────────────┘
                 │
                 ▼
┌─────────────────────────────────┐
│ WebSecuritySDK Recon Run        │
│ Tool Raw Output                 │
│ → EvidenceArtifactRecord        │
│ → Deterministic Parser          │
│ → ObservationRecord             │
│ → Validated Observation Store   │
│ → Normalization                 │
│ → EndpointDefinition            │
│ → TargetModel                   │
└────────────────┬────────────────┘
                 │
                 ▼
┌─────────────────────────────────┐
│ TargetModel vs Ground Truth     │
│ Integration Comparator          │
└────────────────┬────────────────┘
                 │
                 ▼
┌─────────────────────────────────┐
│ Verification Report             │
│ (Precision, Recall, Discovered  │
│ Inputs & Discovery Sources)     │
└─────────────────────────────────┘
```

---

## 8. Discovered Limitations & Edge Cases

1. **Cloudflare Gateway Headers**: Production Cloudflare Workers inject headers (`cf-ray`, `date`, `server: cloudflare`, `report-to`, `nel`). The SDK's HTTP metadata parser and comparator should ignore these CDN-layer headers when evaluating application response headers.
2. **Workers Static Assets Routing**: In Cloudflare Workers with Static Assets, `assets.run_worker_first: true` is required so that unmapped paths fallback to the Worker's deterministic JSON 404 handler rather than Cloudflare's default asset 404 page.
3. **Nested JSON Parsing**: The existing SDK OpenAPI parser does not yet support dot-notation extraction for nested object bodies. The ground-truth files record `filters.category` and `shipping.city` with their respective parents. This provides a ground-truth benchmark to expose and validate future SDK parser enhancements.
