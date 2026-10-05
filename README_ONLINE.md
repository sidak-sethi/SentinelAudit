# Online threat intelligence and research

The Online pipeline lives in `app/`. It gathers security events from NVD and
configured research feeds, enriches identifiers with OSV, GitHub Advisories,
CISA KEV, and EPSS, applies Python relevance filtering, runs LLM triage and
deeper analysis, and uses the research subsystem to collect reproduction and
countermeasure evidence. It then writes a Guard-compatible package to the
same outbox used by the existing Guard and Offline workflows.

## Setup

Use Python 3.11 or newer and install the repository's complete requirements:

```bash
pip install -r requirements.txt
```

Copy `.env.example` to `.env` and set `LLM_API_KEY` for the configured Online
provider. The Online defaults use Groq models; OpenAI and Gemini are also
supported through `LLM_PROVIDER` and `LLM_TRIAGE_PROVIDER`. NVD and GitHub
tokens are optional and can improve request limits. Keep `.env` local.

The research sandbox defaults to Docker with networking disabled. Local
subprocess research is disabled unless `ALLOW_LOCAL_SANDBOX=true` is set and
is not a security boundary for hostile artifacts. Live collection contacts
configured public feeds and the configured LLM provider.

## Dashboard flow

Start the backend and frontend as described in `README_OFFLINE.md`, then use
**Online security research → Run intelligence cycle**. This runs one cycle;
it does not start a background poller. The Online exporter writes packages to
`communication.paths.ONLINE_OUTBOX`, and the route immediately runs Guard's
normal validation and moves approved packages to `offline_workspace/offline_inbox`.
The dashboard lists approved packages in the **Local audit queue**.

Select a repository already scanned by the dashboard, then choose **Audit &
patch** on a queued package. The backend asks for confirmation, checks that the
checkout is clean, revalidates the package, and runs the existing Offline
audit. If the vulnerability is confirmed, the established patch loop may
apply a tested fix and commit it on a local branch. It does not push to
GitHub. A rejected Guard package never reaches the queue.

Each threat package is treated as untrusted data even after AI analysis.
The exporter maps only allowlisted fields into the `communication/schema.py`
contract, computes its integrity digest, and Guard checks the digest, schema,
source URL, sizes, and suspicious content. Do not relax Guard validation to
fit the Online model.

## CLI

Run one live cycle without the dashboard:

```bash
python -m app.main --once
```

Run repeated collection from the CLI:

```bash
python -m app.main --continuous
```

The dashboard endpoint always starts one cycle only. It never starts a
continuous worker in the background.

The deterministic full-flow fixture is available without contacting public
sources or an LLM provider:

```bash
python -m app.main --demo
```

The Online pipeline's state and research artifacts are stored under the
configured `SENTINEL_WORKSPACE` by default. Its outbox is shared with Guard;
do not configure Online to write to an unrelated outgoing directory.

See `app/config.py` for the remaining rate, provider, collector, retry, and
sandbox settings. Keep credentials and runtime artifacts local; they are not
part of the source tree.
