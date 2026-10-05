# SentinelAudit Online — Debug Report

Date: 2026-10-05

## Validation baseline

The uploaded handover describes a free-tier MVP with a 2-threat-per-cycle cap, persistent pending work, compact structured analysis, and bounded retries/quarantine. The repository was unpacked without its bundled Windows virtual environment and audited against that description.

Before changes:

- `pytest -q`: 17 passed.
- `python -m app.main --demo`: passed and exported a valid `ThreatPackage`.
- The code did not yet implement the handover's retry metadata/quarantine requirements.
- The effective deep-analysis output budget was 1,200 tokens because `Settings` clamped free-tier mode to 1,200, while the handover's latest target was 2,400.

## Fixes applied

### 1. Deep-analysis output budget

Changed the effective free-tier deep-analysis cap from 1,200 to 2,400 tokens. The example environment file now matches the actual free-tier configuration instead of advertising values that are immediately clamped.

### 2. Structured-output compactness

Added explicit output limits to the deep-analysis prompt: bounded list sizes, concise strings, mandatory population of required fields, and `unknown` / `not established` / `[]` fallbacks.

The Pydantic schema now also constrains generated list sizes (`maxItems`), so the same compactness requirement exists at the structured-output boundary rather than relying only on prose instructions.

### 3. Retry metadata and quarantine

Added persistent `PendingThreat` records with:

- `retry_count`
- `last_error`
- `last_attempt_at`
- `status` (`pending`, `retry`, `quarantined`)

After the third failed attempt, a threat is retained for diagnostics but is excluded from future processing slots. Existing state entries without the new fields are still read as `pending` with retry count 0.

### 4. Quarantine cannot be reintroduced by enrichment

Both pre-enrichment and post-enrichment group construction now exclude quarantined threat IDs. This closes a subtle loop where enrichment could have recreated a quarantined CVE and consumed a slot again.

### 5. No-work cycles no longer initialize the LLM stack

The LLM analyzer is now constructed only when there are selected groups. This prevents an idle cycle from failing simply because an API key is absent or a provider is unavailable.

### 6. Deterministic research-feed event IDs

Replaced Python's process-randomized `hash()` with a stable SHA-256-derived identifier. Research items without CVE/GHSA identifiers can now be deduplicated consistently across process restarts.

### 7. Tests

Added regression coverage for retry persistence, third-attempt quarantine, no-work LLM initialization, deterministic research event IDs, legacy pending-state compatibility, and pending/current merge behavior.

Current result: **24 tests passed**.

## Reproduced behavior

A simulated failing deep-analysis cycle was run through the real `run_cycle()` orchestration:

```text
cycle 1: retry_count=1, status=retry
cycle 2: retry_count=2, status=retry
cycle 3: retry_count=3, status=quarantined
cycle 4: processed_groups=0, pending_groups=0, quarantined_groups=1
```

This proves the repeatedly failing threat no longer monopolizes the 2-threat processing budget.

## End-to-end deterministic demo

```text
[DEMO] triage={...}
[DEMO] reproduction=REPRODUCED
[DEMO] verification=VERIFIED
[DEMO] exported=data/outgoing/PKG-*.json
```

The generated package was parsed back through the `ThreatPackage` Pydantic model successfully.

## Live-run limitation in this environment

A live `--once` execution could not complete here because external DNS/network access is unavailable in the execution environment, and no Groq API key is present in the uploaded project. The observed failure was therefore environmental, not evidence that the Groq integration itself is broken. The provider's OpenAI-compatible Responses API path remains covered by the mocked provider test.

## Remaining architectural gaps

The repository is now a stable free-tier MVP, but the handover should not be read as proof that live CVE reproduction is fully implemented. `ArtifactResolver` can resolve a PyPI source artifact URL, but `ResearchEngine` does not currently download that artifact into the research flow, and `Reproducer` only executes deterministic `fixture://` cases. Consequently, ordinary live CVEs without a fixture remain `INCONCLUSIVE`.

A second design concern remains: any collector or enrichment failure currently prevents checkpoint advancement. Because OSV, CISA KEV, GitHub Advisories, and the research feed are supplementary sources, freezing the source checkpoint on one enrichment outage can cause repeated re-fetching. That is safe against loss but inefficient and should be redesigned once the MVP is stable.

## Recommended run order

```powershell
pytest -q
python -m app.main --demo
python -m app.main --once
```

For a live run, populate `.env` with the provider key first.
