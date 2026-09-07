# ShadowBoard Frontend — AI Security Assessment Dashboard

ShadowBoard's frontend is a zero-dependency, ultra-fast cybersecurity executive dashboard designed for AI security policy evaluation and live attack visualization.

---

## Key Features

1. **Live Attack Trace & Dialogue Inspector**:
   - Real-time Server-Sent Events (SSE) streaming of active security probes across 100+ turns.
   - Expandable inspector drawers displaying the exact **📤 Attacker Prompt (Sent)** and **📥 Target Model Reply (Received)** with 1-click clipboard copying.
   - Interactive stance filtering (`All`, `Blocked`, `Bypassed`).

2. **RAG Knowledge Base & Document Corpus Viewer**:
   - Accessible from the dashboard header for RAG-instrumented targets.
   - Ingests and inspects 14 enterprise documents (6 PDFs + 8 Markdown files).
   - Filterable by clearance tiers:
     - `Restricted / Confidential` (Executive compensation grids, Project Titan M&A strategy, master secrets)
     - `External Ingested / Trojan` (Trojan vendor invoice, candidate resume with indirect prompt injections)
     - `Public Internal` (Employee handbook, IT support FAQ, holiday leave policy)

3. **Comparative Retesting & Regression Replay**:
   - 1-click automated A/B mitigation retest (Unmitigated Baseline vs. Hardened Defense).
   - Exploit replay modal verifying if security patches eliminate confirmed vulnerabilities.

4. **Cryptographic Non-Repudiation & Audit Vault**:
   - Visual inspection of SHA-256 evidence hashes for every confirmed vulnerability.
   - Chronological scan history with zero overwrites.

---

## Tech Stack

- **Framework**: React 18 (Browser Runtime via Babel & React CDN)
- **Styling**: Tailwind CSS (Executive Red-Black Obsidian Theme `#070709`, `#111116`, `#e11d48`)
- **Typography**: Plus Jakarta Sans & JetBrains Mono
- **Streaming**: Native HTML5 Server-Sent Events (`EventSource`)
- **Serving**: Mounted and served directly by FastAPI from `frontend/index.html` at `http://127.0.0.1:8000/` with zero node_modules setup required.
