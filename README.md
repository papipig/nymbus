# nymbus
Identity abstraction bus / The anonymity layer for AI

## Project motivation

Modern AI assistants are powerful — but they are also data sinks. Every prompt sent
to an external LLM (Claude, ChatGPT, GPT-4, etc.) leaks context: hostnames, IP
addresses, usernames, company names, file paths, credentials, and other sensitive
artefacts that the model does not need in order to reason well.

This is a blocker in many professional contexts:

- **Penetration testers** auditing a client network cannot afford to reveal the
  target's infrastructure to a third-party AI provider.
- **Legal and compliance teams** must not send PII or confidential documents outside
  their trust boundary.
- **Security researchers** working on undisclosed vulnerabilities need analytical
  power without disclosure risk.
- **Enterprises** subject to data-residency regulations cannot route raw internal
  data through foreign cloud APIs.

**nymbus** sits between the user and any external AI model and acts as a
bidirectional anonymisation proxy. Before a prompt leaves the user's environment,
nymbus replaces every sensitive token with a consistent pseudonym. When the model
replies, nymbus reverses the substitution so the user reads real values — while the
model never saw them.

The result: full LLM capability, zero data exposure.

Nymbus is maintaining a consistent semantic graph of identifiers across multiple prompts, 
multiple agents, long-running investigations, tool outputs (Nmap, BloodHound, Nessus, Burp, etc.).

---

## Design

### Three-layer decomposition

```
┌──────────────────────────────────────────────────────────────────────┐
│  LAYER 1 — User Interface                                            │
│  (runs on-premises, fully offline)                                   │
│                                                                      │
│  ┌─────────────┐  ┌──────────────────┐  ┌────────────────────────┐  │
│  │  CLI        │  │  Internal agents │  │  Pipe / file input     │  │
│  │  (single-   │  │  (scripts, loops)│  │  (nmap, burp, nessus…) │  │
│  │   shot)     │  │                  │  │                        │  │
│  └──────┬──────┘  └────────┬─────────┘  └────────────┬───────────┘  │
│         └─────────────────┬┘                          │              │
│                           └───────────────────────────┘              │
│                                        │                             │
│                              raw text / prompt                       │
└────────────────────────────────────────┼─────────────────────────────┘
                                         │
                                         ▼
┌──────────────────────────────────────────────────────────────────────┐
│  LAYER 2 — Anonymisation Proxy                                       │
│  (runs on-premises, fully offline)                                   │
│                                                                      │
│   ┌──────────────────────────────────────────────────────────────┐   │
│   │  AnonymisationEngine                                         │   │
│   │                                                              │   │
│   │  ┌─────────────────────────┐  ┌──────────────────────────┐    │   │
│   │  │  Tier 1  (always runs)  │  │      Pseudonym Vault     │    │   │
│   │  │  Regex + spaCy NER      │  │  real  ↔  isomorphic     │    │   │
│   │  │  IP/CIDR/FQDN/email/…   │─▶│           fake           │    │   │
│   │  │  persons / orgs / locs  │  │  203.0.113.42             │    │   │
│   │  │  custom wordlists       │  │    ↕  198.51.100.7       │    │   │
│   │  └─────────────────────────┘  │  acme-corp.internal      │    │   │
│   │           │ ambiguous spans   │    ↕  zenith-corp…        │    │   │
│   │           ▼                   │  john.doe                │    │   │
│   │  ┌─────────────────────────┐  │    ↕  marc.chen          │    │   │
│   │  │  Tier 2  (on demand)    │  │  (session-scoped,        │    │   │
│   │  │  Local LLM              │─▶│   0600 JSON,            │    │   │
│   │  │  type reclassifier      │  │   reversible)            │    │   │
│   │  │  "Is 'Phoenix' here a   │  └──────────────────────────┘    │   │
│   │  │   person or city?"      │  (backend: nymbus.yaml           │   │
│   │  │  (ollama/mistral/…,     │   local_llm_model key)           │   │
│   │  │  or any LiteLLM model   │                                   │   │
│   │  │  string)                │                                   │   │
│   │  └─────────────────────────┘                                   │   │
│   │                                                              │   │
│   │  ┌──────────────────────────────────────────────────────┐   │   │
│   │  │  Watchdog  (runs on every pass, blocks on failure)   │   │   │
│   │  │                                                      │   │   │
│   │  │  FORWARD (before sending to external LLM)            │   │   │
│   │  │  ① Completeness  deanon(anon(x)) == x ?              │   │   │
│   │  │    ✗ → raise AnonymisationError, block               │   │   │
│   │  │  ② Exact scan    real_val ∈ anon(x) ?                │   │   │
│   │  │    ✗ → raise LeakDetectedError, log, block           │   │   │
│   │  │  ③ LLM scan      "does anon(x) leak real data?"      │   │   │
│   │  │    ✗ → block  (warn-only: --allow-semantic-warn)     │   │   │
│   │  │                                                      │   │   │
│   │  │  BACKWARD (after external LLM reply)                 │   │   │
│   │  │  ④ Alias residue  alias ∈ deanon(reply) ?            │   │   │
│   │  │    ✗ → warn (LLM hallucinated unknown identifier)    │   │   │
│   │  └──────────────────────────────────────────────────────┘   │   │
│   └──────────────────────────────────────────────────────────────┘   │
│                                                                      │
│   forward pass  →  anonymised prompt  (only after watchdog ✓)        │
│   backward pass ←  de-anonymised reply (only after watchdog ✓)       │
└────────────────────────────────────────┬─────────────────────────────┘
                                         │  anonymised text only
                                         ▼
┌──────────────────────────────────────────────────────────────────────┐
│  LAYER 3 — External LLM Connectors                                   │
│  (cloud / third-party, untrusted)                                    │
│                                                                      │
│   ┌──────────────┐  ┌──────────────┐  ┌──────────────┐              │
│   │  OpenAI      │  │  Anthropic   │  │  Mistral     │  …           │
│   │  (GPT-4o…)   │  │  (Claude…)   │  │              │              │
│   └──────────────┘  └──────────────┘  └──────────────┘              │
│                  unified via LiteLLM adapter                         │
└──────────────────────────────────────────────────────────────────────┘
```

---

### Component breakdown

#### Layer 1 — User Interface

| Sub-component | Role |
|---|---|
| **CLI** | `nb` single-shot invocation; session file provides multi-turn continuity; `rich` inline transparency output |
| **Internal agents** | Scripts or loops that feed tool output (Nmap XML, BloodHound JSON, Nessus reports…) directly into nymbus as programmatic callers |
| **Pipe / file mode** | `cat report.txt \| nb "summarise vulnerabilities"` — fully scriptable |

All three share the same Python API surface (`Session.send(text) → str`), so the CLI is just one driver among several.

#### Layer 2 — Anonymisation Proxy

**Detection — two tiers**

Tier 1 always runs on every prompt (~10-50ms, no model required). Tier 2
fires only on spans where Tier 1 yields a low-confidence or ambiguous type.

**Tier 1 — fast, deterministic**

- **Regex detector**: pre-compiled patterns for IPv4/IPv6, CIDR, MAC, FQDN,
  e-mail, URL, file path, hash (MD5/SHA), `KEY=value` credentials, UUIDs.
- **spaCy NER** (`en_core_web_sm`, offline): maps entity labels (`PERSON`,
  `ORG`, `GPE`) to nymbus types. Fast CPU inference, no network required.
- **Custom detector**: user-supplied regex patterns or wordlists loaded from
  `nymbus.yaml`, compiled at startup.

**Tier 2 — LLM type reclassifier** (on ambiguous spans only, ~200-500ms)

The backend is the `local_llm_model` key in `nymbus.yaml` (see
[Configuration](#configuration) below). This **must be a local/on-prem endpoint**
(Ollama, vLLM, llama.cpp, LM Studio, etc.) — watchdog ③ sends real vault values
to it for semantic checking, so a cloud API here would be a data leak. Tier 2
fires when spaCy's NER confidence for a span falls below `tier2_threshold`
(default `0.85`).

```
"Phoenix"  in "… pivot to Phoenix next …"  →  PERSON ? GPE ? CODENAME ?
```

Tier 2 never fires for clear-cut structured tokens (IPs, FQDNs, emails).
When `local_llm_model` is unset, Tier 2 is disabled and ambiguous spans
fall back to the spaCy label.

**Pseudonym Vault — isomorphic substitution, not opaque tokens**

The core principle: a fake value must be the same *shape* as the real one. The LLM
must still reason about structure — that `accounting` is a department subdomain, that
a private IP is an internal host, that a path has a certain depth. Only the
*identifying* fragments are replaced.

```
  ✗  naive (loses context)
     accounting.acme-corp.com  →  HOST-05
     the LLM cannot reason about department, domain, or hierarchy

  ✓  isomorphic (preserves context)
     accounting.acme-corp.com  →  accounting.zenith-corp.com
     the LLM understands: subdomain = department, corporate FQDN — same logic applies
```

Each token type has a dedicated isomorphic generator:

| Type | Real value | Fake value | Preserved | Replaced |
|---|---|---|---|---|
| FQDN | `accounting.acme-corp.com` | `accounting.zenith-corp.com` | subdomain, TLD, depth | company SLD |
| IPv4 private | `192.168.1.50` | *(unchanged)* | all octets | — |
| IPv4 public | `203.0.113.42` | `198.51.100.7` | routable class | exact octets |
| CIDR private | `192.168.1.0/24` | *(unchanged)* | all | — |
| CIDR public | `203.0.113.0/24` | `198.51.100.0/24` | prefix length | network address |
| Email | `j.doe@acme-corp.com` | `m.chen@zenith-corp.com` | local format, domain shape | name, company |
| Username | `john.doe` | `marc.chen` | format (first.last) | actual name |
| Person name | `John Doe` | `Marc Chen` | first + last structure | actual name |
| Org name | `Acme Corp` | `Zenith Corp` | corporate suffix style | company name |
| File path (Unix) | `/home/john/reports/` | `/home/marc/reports/` | depth, dir names | user segment |
| File path (Win) | `C:\Users\john\Desktop` | `C:\Users\marc\Desktop` | drive, depth, structure | user segment |
| Hash | `5f4dcc3b5aa765...` | `3c59dc048e885...` | length, hex format | hex content |

> **Private addresses are not substituted.** RFC 1918 ranges (`10.x`, `172.16–31.x`,
> `192.168.x`) and their CIDRs carry no identifying information — no organisation
> can be inferred from them — and replacing them would break subnet topology
> reasoning (e.g. switching a /24 from 192.168 to 10 changes the apparent network
> class and invalidates any routing or segmentation analysis the LLM might perform).

**Cross-type consistency**: the vault shares a company-name namespace, so `acme-corp`
becomes `zenith-corp` everywhere it appears — in FQDNs, email domains, and free text
— giving the LLM a fully coherent, self-consistent fake world.

**Storage**: in-memory during a session; persisted to a JSON file (`chmod 0600`)
for investigations spanning multiple invocations. The reverse map (`fake → real`)
is kept alongside for O(1) de-anonymisation of model replies.

**Session context** — conversation history is stored in anonymised form, so multi-turn
exchanges remain coherent to the LLM without accumulating any real data.

**Forward pass sequence**

```
raw text
  │
  ① Tier 1: regex + spaCy detect spans              ~10-50ms
  │
  ② Tier 2: local LLM reclassifies ambiguous spans  ~0-500ms
  │
  ③ Isomorphic substitution → anon(x)               ~1ms
  │
  ④ Watchdog ①: deanon(anon(x)) == x ?              ~1ms    → block on fail
  │
  ⑤ Watchdog ②: exact scan (real ∉ anon(x))         ~1ms    → block on fail
  │
  ⑥ Watchdog ③: LLM semantic scan                   ~500ms  → block on LEAK
  │
send to external LLM (Layer 3)
```

**Watchdog** — the trust barrier

The watchdog wraps every forward and backward pass. Checks ①②③ hard-block
by default; ④ is a soft warning.

| Check | Direction | Default | What it catches |
|---|---|---|---|
| ① Completeness `deanon(anon(x)) == x` | Forward | Hard block | Bugs in the anonymisation pipeline |
| ② Exact scan `real ∉ anon(x)` | Forward | Hard block | Detector misses, exact token leaks |
| ③ LLM semantic scan | Forward | Hard block (`--allow-semantic-warn` to soften) | Implicit / paraphrased leaks |
| ④ Alias residue `alias ∉ deanon(reply)` | Backward | Soft warning | LLM-hallucinated identifiers with no vault mapping |

- **Check ①** recomputes `deanon(anon(x))` and diffs against the original.
  Any divergence means a token was transformed irreversibly — prompt is dropped.
- **Check ②** exact-matches every vault real value against `anon(x)` (including
  case-folded variants). Any hit drops the prompt; position logged locally,
  never sent anywhere.
- **Check ③** sends a short structured prompt to the configured `local_llm_model`:
  *"Given these sensitive values, does this anonymised text reveal any of them?"*
  Scoped to only vault values referenced in the current turn (keeps the prompt
  small even in long sessions). Replies `CLEAN` or `LEAK: <reason>`. Hard
  blocks by default; pass `--allow-semantic-warn` to downgrade to a warning.
  If no `local_llm_model` is configured, Check ③ is skipped and a warning is emitted.
- **Check ④** scans the de-anonymised reply for unreplaced alias tokens. Warns
  but does not block — this is a coherence issue, not a data leak.

#### Layer 3 — LLM Connectors

A thin abstract `LLMClient` interface (`complete(messages) → str`) with concrete adapters:

- OpenAI (GPT-4o, GPT-4…)
- Anthropic (Claude 3.x…)
- Mistral or Ollama — for fully air-gapped operation using local models

[LiteLLM](https://github.com/BerriAI/litellm) can serve as a universal router so adding a new provider requires only a model string, not new code.

---

### Internal architecture

**Multi-turn conversation** works across invocations via the session file: on
startup `nb` loads the anonymised message history and reconstructs the full
`messages` array before calling the external LLM. The LLM API is stateless —
you pass the whole history every time — so the model sees a coherent conversation
regardless of how many separate `nb` invocations produced it.

```
┌─────────────────────────────────────┐
│  nb process (single Python process) │
│                                     │
│  run once, exit                     │
│    └─▶ Session.load()               │  ← rebuilds messages[] from .nbs
│    └─▶ AnonymisationEngine          │
│           ├── Detectors (Tier 1/2)  │
│           ├── PseudonymVault        │
│           └── Watchdog              │
│    └─▶ LiteLLM connector ──────────────▶ external LLM (full history sent)
│    └─▶ Session.save()               │  ← appends new turn, atomic rename
└─────────────────────────────────────┘
```

**Session files.**
Each session is stored as a JSON file (`chmod 0600`):

```
~/.local/share/nb/sessions/
  default.nbs          # used when no --session flag is given
  pentest-acme.nbs     # nb --session pentest-acme
  recon-2026-06.nbs    # nb --session recon-2026-06
```

A `.nbs` file contains the vault (forward + reverse pseudonym maps) and the
anonymised conversation history. It is loaded into memory at startup and written
back after every turn using an atomic POSIX rename (`write to .nbs.tmp` →
`os.rename()`), so a crash mid-write never corrupts the previous state.

**Session isolation and concurrency.**

| Scenario | Behaviour |
|---|---|
| Two `nb` processes with **different** session IDs | Fully isolated — separate files, no shared state |
| Two `nb` processes with the **same** session ID | Second process acquires an `fcntl` advisory lock, gets `SessionLockedError`, and exits with a clear message |
| Script piping output while REPL is open | Use a different session ID for the script (`nb --session script-feed`) |

The vault is purely in-memory while `nb` is running. Nothing is written to the
session file mid-substitution — only the completed, watchdog-cleared state is
persisted.

---

### CLI interface

The binary is `nb`. Sending a prompt is the default action — no subcommand required.

**Basic usage**

```
nb scan all corp networks in acme-corp.internal
nb "what open ports did you find?" -- nmap -sV 192.168.1.0/24
cat report.txt | nb "summarise critical findings"
```

**LLM-generated commands**

After receiving the external LLM's reply, the local LLM (`local_llm_model`)
classifies whether it contains a shell command. This is the same model already
used for Tier 2 and watchdog ③ — no extra dependency. If it returns a command,
`nb` de-anonymises it and presents it for validation before executing anything
(same approval flow as VS Code's agent command execution):

```
$ nb scan all corp networks in acme-corp.internal

  ── anon ──────────────────────────────────────────────────────────
  [SUBST]  acme-corp.internal  →  zenith-corp.internal   FQDN / org
  [OK   ]  watchdog ① ② ③ passed
  ──────────────────────────────────────────────────────────────────

  ┌── suggested command ────────────────────────────────────────────┐
  │  nmap -sV --open -T4 acme-corp.internal                        │
  └─────────────────────────────────────────────────────────────────┘
  [y] Execute   [e] Edit   [n] Cancel
```

The LLM reasoned with `zenith-corp.internal`; the user sees and runs
`acme-corp.internal`. Output from the executed command is captured,
anonymised, and fed back as context for the next turn.

**Shell command execution**

`nb` can run a shell command, capture its stdout, anonymise the output, and
inject it as context before the prompt. The `--` separator marks the start of
the shell command:

```
nb "explain these results" -- nmap -sV 192.168.1.0/24
nb "who has DA?" -- python bloodhound_query.py --find-da
nb -- nmap -sV 192.168.1.0/24    # capture + anonymise, print result, exit
```

Shell commands are **blocked by default** until explicitly allowed.
On first encounter `nb` prompts interactively:

```
  ⚠  Execute shell command?
     nmap -sV 192.168.1.0/24

  [y] Yes (once)   [A] Always allow 'nmap'   [n] No   [D] Always deny 'nmap'
```

Persistent rules are saved to `~/.local/share/nb/shell_rules.yaml`.
Shell allow/deny lists can also be seeded in `nymbus.yaml` (see
[Configuration](#configuration) below).

**Transparency log**

Every anonymisation event is printed inline so you can see exactly what left
your environment — and what didn't. After each turn `nb` prints a compact
summary; `-v` expands it to the full event list:

```
$ nb scan all corp networks

  ── anon ─────────────────────────────────────────
  2 substitutions · 1 pass · watchdog ✓
  ─────────────────────────────────────────────────

Here is a scan plan for zenith-corp.com …
```

```
$ nb scan all corp networks -v

  ── anon ────────────────────────────────────────────────────────────
  [SUBST]  acme-corp.com   →  zenith-corp.com   FQDN / org
  [PASS ]  192.168.1.50    (private, unchanged)  IPv4 private
  [SUBST]  john.doe        →  marc.chen         username
  [WARN ]  "corp" — low confidence (ORG vs. common word), kept as ORG
  [OK   ]  watchdog ① ② ③ passed
  ────────────────────────────────────────────────────────────────────

Here is a scan plan for zenith-corp.com …
```

The same format applies in pipe mode. Pass `--log-file <path>` to write the
full transparency log (with ANSI colours) to a file — suitable for `tail -f`
in a split pane during long sessions.

**Flags**

| Flag | Effect |
|---|---|
| `-v` / `--verbose` | Show substitution events inline (non-interactive mode) |
| `-d` / `--debug` | Full debug: Tier 1/2 spans, vault ops, watchdog trace |
| `-q` / `--quiet` | Suppress all transparency output |
| `--log-file <path>` | Write transparency log to file (ANSI colours, `tail -f` friendly) |
| `--allow-semantic-warn` | Downgrade watchdog ③ from hard block to warning |
| `--model <string>` | Override `external_llm_model` for this session |
| `--session <id>` | Resume a named session (vault + history restored); overrides `NB_SESSION` |
| `--no-shell` | Disable `--` command execution entirely |

> **`NB_SESSION`** — set this environment variable to make every `nb` invocation in the
> current shell automatically attach to a named session without typing `--session`:
> ```
> export NB_SESSION=pentest-acme
> nb scan all corp networks in acme-corp.internal   # attaches to pentest-acme
> ```
> `--session` on the command line always wins if both are present.

**Session management**

```
nb session new [name]     # start a fresh vault + history
nb session list           # list saved sessions with timestamps
nb session export <id>    # export de-anonymised transcript
```

---

### Configuration

All settings live in `nymbus.yaml` (searched in `$PWD`, then `~/.config/nb/`).
Every key can also be set as an environment variable using the `NB_` prefix
(e.g. `NB_EXTERNAL_LLM_MODEL=anthropic/claude-opus-4`).

```yaml
# nymbus.yaml — full reference

# ── Layer 3: external LLM (the model your prompts are sent to) ──────────────
external_llm_model: "anthropic/claude-opus-4"   # any LiteLLM model string
# external_llm_model: "openai/gpt-4o"
# external_llm_model: "mistral/mistral-large-latest"
# external_llm_model: "ollama/llama3"           # fully air-gapped, no API key needed

# ── Layer 2: local LLM (Tier 2 reclassifier + watchdog ③ + command detect) ──
# MUST be a local/on-prem endpoint — watchdog ③ sends real vault values to
# this model for semantic checking, so a cloud API would be a data leak.
local_llm_model: "ollama/mistral"               # Mistral running locally via Ollama
# local_llm_model: "ollama/llama3"
# local_llm_model: "ollama/phi3"
# Any local inference server with an OpenAI-compatible API works too:
# local_llm_model: "openai/mistral"             # model name on your local server
# local_llm_api_base: "http://localhost:8000"    # vLLM / llama.cpp / LM Studio
tier2_threshold: 0.85   # spaCy NER confidence below this → escalate to Tier 2

# ── Shell execution ──────────────────────────────────────────────────────────
shell:
  confirm: true                            # always prompt (default: true)
  allow: ["nmap", "curl", "cat", "grep"]   # pre-approved, no prompt
  deny:  ["rm", "dd", "mkfs"]              # hard-blocked, never executed
```

Minimal config to get started (everything else defaults):

```yaml
external_llm_model: "anthropic/claude-opus-4"
local_llm_model: "ollama/mistral"
```

**API keys** are not managed by nymbus. LiteLLM reads them directly from your
shell environment using the provider's standard variable names:

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
export OPENAI_API_KEY="sk-..."
export MISTRAL_API_KEY="..."
```

If you use Ollama for both models (`ollama/…`), no API keys are needed at all.

---

### Technology stack

| Concern | Choice | Rationale |
|---|---|---|
| Language | Python 3.11+ | Best ecosystem for NLP + LLM SDKs |
| CLI | `typer` + `rich` | `typer` for arg parsing; `rich` for colours and inline transparency output |
| Regex detection | stdlib `re` / `regex` | Zero dependencies, fast |
| Offline NER | `spaCy` + `en_core_web_sm` | Offline, well-maintained, fast CPU inference |
| Data models / config | `pydantic` v2 | Validation, `.env` / YAML loading |
| LLM routing | `litellm` | Single interface for 100+ providers |
| Local LLM | any local inference server (Ollama, vLLM, llama.cpp…) via LiteLLM | Tier 2 reclassifier, watchdog ③, command detection — endpoint must be on-prem; a cloud API here would leak real vault values |
| Tests | `pytest` + `hypothesis` | Property-based tests for round-trip correctness |

---

### Repository layout

```
nymbus/
├── nymbus/
│   ├── cli/
│   │   ├── main.py            # `nb` entry point — arg parsing, REPL loop, pipe mode
│   │   ├── shell.py           # Shell command runner — allow/deny rules, interactive prompt
│   │   └── transparency.py    # TransparencyLog — collects SUBST/WARN/OK events, renders via rich
│   ├── proxy/
│   │   ├── engine.py          # AnonymisationEngine (orchestrates detect→replace→restore)
│   │   ├── vault.py           # PseudonymVault (forward + reverse maps, persistence)
│   │   ├── pseudonyms.py      # Isomorphic generators (FQDN, IP, name, path, hash…)
│   │   ├── watchdog.py        # Checks ①②③ (forward) and ④ (backward)
│   │   ├── local_llm.py       # Thin wrapper: calls LiteLLM with local_llm_model string
│   │   │                      # (same litellm.completion() as external, different model + api_base)
│   │   └── detectors/
│   │       ├── base.py        # Detector ABC
│   │       ├── regex_det.py   # IP, CIDR, MAC, email, FQDN, path, credential patterns
│   │       ├── ner_det.py     # spaCy offline NER wrapper (Tier 1)
│   │       └── custom_det.py  # User-defined rules (regex / wordlists)
│   ├── connectors/
│   │   ├── base.py            # LLMClient ABC
│   │   └── litellm_conn.py    # LiteLLM adapter — both external and local models use this;
│   │                          # local_llm_model and external_llm_model both call litellm.completion()
│   ├── session/
│   │   └── context.py         # Multi-turn history, session lifecycle
│   └── config.py              # Pydantic settings (env vars / nymbus.yaml)
├── tests/
│   ├── test_vault.py
│   ├── test_detectors.py
│   ├── test_roundtrip.py      # Property-based: deanon(anon(x)) == x for all token types
│   └── test_watchdog.py       # Inject deliberate leaks and bad anon; assert blocks
├── pyproject.toml
└── README.md
```

---
