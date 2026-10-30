# ShadowLens Spec-Driven Development

This repository follows the uploaded **ShadowLens Unified Master Specification** as the source of truth. Requirement IDs and acceptance criteria must accompany implementation commits. A feature is not complete until its tests pass; do not claim P1/P2 functionality is implemented without acceptance tests.

## Product contract
- Local-first AI Shadow IT, sensitive-data exposure, and agent-governance auditing.
- Visibility tiers: **T1 OBSERVED** metadata, **T2 INFERRED** flow-shape, **T3 VERIFIED** authorized plaintext.
- No TLS MITM, certificate injection, or silent HTTPS decryption.
- Raw secrets and prompts are not persisted by default; evidence must be masked.
- LLM triage is advisory only and cannot override deterministic detection.
- Unknown endpoints remain provisional until corroborated.
- Collectors emit normalized metadata and never make security decisions.
- Simulations use synthetic events and never execute described commands.
- Bind local services to loopback by default and disclose partial telemetry coverage.

## Milestone gates
1. **M0 Foundation:** canonical event/finding models, health/coverage endpoint, local persistence, bounded event pipeline, local auth, CI green.
2. **M1 Detection:** deterministic secret/PII rules, validators, redaction, canaries, benchmark.
3. **M2 Providers/collectors:** registry tests, socket metadata, JSONL/HAR ingestion, PCAP metadata.
4. **M3 Agent audit:** tool-call parsing, shell/filesystem/network rules, autonomy and correlation.
5. **M4 Risk/compliance:** explainable risk, policy, controls, flow-shape analysis.
6. **M5 Dashboard:** overview, inventory, alerts, graph, compliance, ingestion and live feed.
7. **M6+ Optional:** simulator, triage, gateway, exports and hardening.

Do not start advanced milestones before the previous gate is testable. The current repository is a hackathon starter and does **not** yet satisfy the full specification. Keep this document honest as each gate is implemented.

## Current implementation notes
- JSON/JSONL event analysis and synthetic demo fixtures exist.
- The deterministic detector supports a small initial subset of secret patterns.
- The opt-in socket snapshot collector emits T1 metadata only; it is not a continuous monitor and cannot inspect encrypted request bodies.
- SQLite persistence, bearer-token authentication, PCAP ingestion, HAR support, full PII validators, complete traceability, and the full dashboard remain pending unless backed by code and tests.
