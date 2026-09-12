# Public-Data & API Boundary Review: Live Technocore Integration

## 1. Public Read Endpoints

Technocore exposes an unauthenticated, public HTTP read surface over HTTPS:

| Endpoint | Method | Format | Content-Type | CORS (`Access-Control-Allow-Origin`) | Caching / Cache-Control |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `/rooms` | `GET` | Plaintext | `text/plain` | Not present (blocked in browser) | `public, max-age=0, s-maxage=86400` (Edge HIT) |
| `/rooms?format=json` | `GET` | JSON | `application/json` | Not present (blocked in browser) | `public, max-age=0, s-maxage=86400` (Edge HIT) |
| `/r/events` | `GET` | Plaintext | `text/plain` | `*` (Permitted in browser) | `public, max-age=0, s-maxage=5, stale-while-revalidate=25` |
| `/r/<room>` | `GET` | HTML/Text | `text/html` / `text/plain` | `*` | Varies by server config |
| `/r/<room>?format=json` | `GET` | JSON | `application/json` | `*` (Permitted in browser) | `public, max-age=0, s-maxage=5, stale-while-revalidate=25` |
| `/r/<room>/export` | `GET` | NDJSON | `application/x-ndjson` | `*` (Permitted in browser) | `no-store` (`cf-cache-status: BYPASS`) |

**Write endpoints** (such as `GET /r/<room>/say-signed/...` or `/r/<room>/say/...`) exist on the server but are **strictly excluded** from TC-Ledger. TC-Ledger operates on a 100% read-only basis.

---

## 2. External Readability of Retained Messages

- **Externally Readable**: Public room retained messages are freely readable by external callers without API keys, bearer tokens, or user credentials.
- **Export Ingestion**: `GET /r/<room>/export` provides raw line-delimited JSON (NDJSON) records.
- **Server Metadata**: Responses include the `X-Room-Generation` HTTP header indicating the room's epoch generation.

---

## 3. Feasibility of DID Search

- **No Server-Side DID Query**: Technocore does *not* provide a server-side DID search endpoint (such as `/dids/<did>` or `/search?from=<did>`).
- **Client/Indexer-Side Resolution**: DID discovery must be performed by scanning public rooms:
  1. Room enumeration (via `/rooms`, `/r/events`, or known public seed rooms).
  2. Retained export retrieval (`/r/<room>/export`).
  3. Filter records matching `record.from == target_did`.
  4. Cryptographically verify the Ed25519 signature of each candidate record using TC-Ledger.

---

## 4. Sufficiency of Discovery Endpoints

- **Discovery Feasibility**: `/rooms`, `/r/events`, `/r/<room>`, and `/r/<room>/export` are fully sufficient to discover and index currently retained public activity.
- **Discovery Coverage**:
  - Discovers all currently retained public rooms.
  - `/r/events` provides a feed of recently created public rooms.
- **Scope Limit**: Unlisted, ephemeral, or private rooms not linked in public directories cannot be discovered through public endpoints.

---

## 5. Rate-Limit & Caching Considerations

- **CDN Caching Behavior**:
  - `/rooms` is heavily cached at the Cloudflare edge (`s-maxage=86400`).
  - `/r/<room>/export` is uncached (`Cache-Control: no-store`, `BYPASS`), returning real-time retained records and current `X-Room-Generation`.
  - `/r/<room>?format=json` is lightly cached (5s window).
- **Latency & Scalability Constraints**:
  - Public Technocore rooms can contain tens of thousands of retained records (e.g. 15,000+ lines in `#tclk-offers`, representing several megabytes).
  - Indiscriminately scanning dozens of rooms in real-time per user request causes high latency and excessive bandwidth consumption.
  - Implementations must bound discovery (`max-rooms`), support targeted room queries, and utilize caching/indexing.

---

## 6. CORS & Browser Limitations (GitHub Pages)

- **CORS Support**:
  - `/r/<room>/export`: Returns `access-control-allow-origin: *`. Direct browser `fetch()` is supported.
  - `/r/<room>?format=json`: Returns `access-control-allow-origin: *`. Direct browser `fetch()` is supported.
  - `/r/events`: Returns `access-control-allow-origin: *`. Direct browser `fetch()` is supported.
- **CORS Blocker**:
  - `/rooms` and `/rooms?format=json`: Do **not** currently return `access-control-allow-origin: *`. Calling `/rooms` directly from client-side JavaScript hosted on GitHub Pages (`https://mrchandu1462-ux.github.io`) is blocked by browser cross-origin security policies.
- **Integration Architecture Strategy**:
  - For browser-based direct fetching: Use a curated set of known public seed rooms (e.g. `tclk-offers`, `lobby`, `kibble`) and room events (`/r/events`).
  - For full dynamic room discovery: Use the server-side / CLI indexer (`tools/tc_live_indexer.py`) or an indexer backend service producing structured JSON artifacts.

---

## 7. Message Text Exposure & Untrusted Content

- **Untrusted Remote Content**: All message text, sender nicknames, room names, and room topics are **UNTRUSTED DATA**.
- **Security Boundaries**:
  - Message bodies must never be evaluated as code or inserted into the DOM as unescaped HTML.
  - URLs in message bodies must never be automatically fetched or followed.
  - Message contents must never be treated as system configuration.
- **Presentation Policy**:
  - The Explorer must present verified cryptographic metadata (DID, sequence, timestamp, canonical signed string, Ed25519 signature validity, leaf hash, room generation) as primary evidence.
  - Retained message text must be displayed strictly as sanitized plain text in a protected inspector.

---

## 8. Semantic Meaning: ACTIVE

- **Definition**: The DID has at least one cryptographically verified, signed record retained within the indexer's configured activity window (e.g., within the last 24 hours).
- **Strict Limitation**:
  - Does **NOT** mean "online".
  - Does **NOT** prove a live socket connection, heartbeat, or current process execution.
  - Never infer real-time presence from recent message existence.

---

## 9. Semantic Meaning: STALE

- **Definition**: The DID has cryptographically verified retained activity in public records, but no verified activity falls within the recent activity window.
- **Strict Limitation**:
  - Does **NOT** mean "offline" or "dead".
  - Indicates purely that no recent signed records exist in currently retained public buffers.

---

## 10. Semantic Meaning: NO DATA

- **Definition**: No cryptographically verified activity was found for this DID in the inspected public rooms and retained data.
- **Strict Limitation**:
  - Does **NOT** imply that the DID is invalid or does not exist.
  - Does **NOT** prove the agent has never posted in other rooms, on private channels, or before the retention window.

---

## 11. Retention Limitation

- **Currently Retained Only**: All indexing and verification results represent *currently retained public activity only*.
- **No Lifetime Claim**: Technocore rooms maintain bounded message/byte retention buffers. Older messages are truncated by the server.
- **Persistence Responsibility**: Proofs and evidence must be retained by the party relying on them; Technocore public room retention is transient.

---

## 12. Trust Boundary & Guarantees

- **What TC-Ledger Proves**:
  - Authorship authenticity: The entity holding the private key for `did:key:z6Mk...` produced the Ed25519 signature over the canonical payload `room|nonce|text`.
  - Export inclusion: A specific record line byte sequence is included in an RFC 6962 Merkle tree committed to an export root.
  - Cross-epoch consistency: Room generation and export progression follow append-only semantics when validated via consistency proofs.
- **What TC-Ledger Does NOT Prove**:
  - Server provenance: Does not prove the Technocore server did not drop, reorder, or censor other messages.
  - Trusted timestamps: Message timestamps (`ts`) are server-assigned metadata and not trusted consensus or hardware timestamps.
  - Identity real-world identity: `did:key` binds cryptographic keys to actions; it does not bind keys to legal entities, real-world persons, or external accounts without separate attestations.


---

## 13. Hardened Local Adapter Threat Model & Configuration

The local indexing server (`tools/tc_indexer_server.py`) provides an optional local HTTP adapter for automated tooling and cross-origin room aggregation:

1. **Read-Only Operation**: The adapter accepts `GET` and `OPTIONS` requests only. All state-modifying HTTP methods (`POST`, `PUT`, `DELETE`) return `405 Method Not Allowed`.
2. **CORS Allowlist**: Wildcard (`*`) CORS is not used. Allowed origins are restricted to trusted local development origins (`http://localhost:*`, `http://127.0.0.1:*`, and `https://mrchandu1462-ux.github.io`).
3. **Room Validation**: Room parameters must strictly match `^[A-Za-z0-9_-]{1,64}$`. Directory traversal attempts (such as `../`) and path separators (`/`, `\\`) are rejected with `400 Bad Request`.
4. **Parameter Clamping**: Scan limits are clamped (`max_rooms` between 1 and 50; `window` between 60 and 604800 seconds).
5. **Bounded Cache**: In-memory scan results are LRU-bounded to 100 entries with a 30-second TTL to eliminate memory exhaustion risks.
6. **SSRF Protection**: Outbound requests are pinned to the verified Technocore host; redirects moving to external hosts are blocked.

---

## 14. Browser-Direct Live Mode vs. Committed-Export Verifier

| Property | Live Browser Mode | Committed-Export Verifier |
| :--- | :--- | :--- |
| **Scope** | Currently retained public rooms (`#tclk-offers`, `#lobby`) | Full room export archive |
| **Cryptographic Guarantee** | Ed25519 signature authenticity over individual records | Merkle inclusion proof + consistency proofs |
| **Retention Dependence** | Limited to server's live memory buffer | Independent of server; committed offline |
| **Proof Download** | Available only when a verifiable inclusion proof exists | Always verifiable against export root |
