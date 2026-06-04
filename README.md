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

---

## Architecture

```
  USER / TOOL
      │
      │  raw prompt (real IPs, names, secrets…)
      ▼
┌────────────────────────────────────────────────────────────────┐
│                          N Y M B U S                           │
│                                                                │
│   ┌────────────────────────────────────────────────────────┐   │
│   │                  Anonymisation Engine                  │   │
│   │                                                        │   │
│   │  ┌──────────────┐        ┌──────────────────────────┐  │   │
│   │  │   Detectors  │        │     Pseudonym Vault      │  │   │
│   │  │              │        │                          │  │   │
│   │  │ • IP / CIDR  │───────▶│  real_val ↔ pseudonym    │  │   │
│   │  │ • Hostnames  │        │  (session-scoped,        │  │   │
│   │  │ • Usernames  │        │   deterministic,         │  │   │
│   │  │ • Credentials│        │   reversible)            │  │   │
│   │  │ • PII / NER  │        └──────────────────────────┘  │   │
│   │  │ • File paths │                                      │   │
│   │  │ • Custom     │                                      │   │
│   │  └──────────────┘                                      │   │
│   └────────────────────────────────────────────────────────┘   │
│                                                                │
│         anonymised prompt ──────────────────────────────────── │
│                                          │                     │
│    ◀── de-anonymised reply               │                     │
│                                          ▼                     │
└────────────────────────────────────────────────────────────────┘
                                           │
                              ┌────────────┴────────────┐
                              │   External AI Provider  │
                              │                         │
                              │  ┌─────────┐ ┌───────┐  │
                              │  │ Claude  │ │  GPT  │  │
                              │  └─────────┘ └───────┘  │
                              │  ┌─────────┐ ┌───────┐  │
                              │  │ Mistral │ │  ...  │  │
                              │  └─────────┘ └───────┘  │
                              └─────────────────────────┘


  Data flow (forward — anonymise):

    "Scan 192.168.1.0/24 for open ports on acme-corp.internal"
                            │
                            ▼  nymbus replaces tokens
    "Scan NET-A for open ports on HOST-001"
                            │
                            └──────────────────▶  LLM

  Data flow (backward — de-anonymise):

    LLM ──▶  "HOST-001 has port 22 open. Try pivoting via NET-A gateway."
                            │
                            ▼  nymbus restores tokens
         "acme-corp.internal has port 22 open. Try pivoting via 192.168.1.1."
                            │
                            └──────────────────▶  USER
```

---
