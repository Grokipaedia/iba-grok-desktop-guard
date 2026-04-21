# iba-grok-desktop-guard

> **Grok on your desktop. Human intent required.**

---

## The Stakes

Grok Build + Grok Computer together form the highest-risk desktop agent in existence.

Grok Build can write code, install packages, modify files, and deploy.
Grok Computer can control your mouse, keyboard, screen, and applications.

Together — without a signed intent certificate — they can do anything your user account can do. Silently. Persistently. Without asking.

**The action is not the authorization. The signed certificate is.**

---

## The Threat Model

Without a signed intent certificate:

- Grok Build can deploy to production without explicit sign-off
- Grok Computer can read your browser history, password manager, and keychain
- A persistent background workflow can continue after your session ends
- Credential files can be read and exfiltrated during a "build" task
- System settings can be modified during a "computer assistance" task
- The agent can install packages, modify IAM policies, or disable logging
- Keylogging can run persistently in the background
- No audit trail proves what was authorized versus what was executed

**An agent with computer control + build + deploy is the attack surface.**

---

## The IBA Layer

```
┌─────────────────────────────────────────────────────┐
│           HUMAN PRINCIPAL                           │
│   Signs grok-desktop.iba.yaml before session        │
│   Declares: permitted Build actions, permitted      │
│   Computer actions, forbidden behaviors, kill       │
│   threshold, hard expiry, DENY_ALL posture          │
└───────────────────────┬─────────────────────────────┘
                        │  Signed Grok Desktop Intent Certificate
                        │  · Identity reference
                        │  · Build scope: create · edit · test · commit
                        │  · Computer scope: click · type · screenshot
                        │  · Forbidden: credentials · keylog · deploy
                        │  · Kill: persistence · exfiltration · disable_security
                        ▼
┌─────────────────────────────────────────────────────┐
│         IBA GROK DESKTOP GUARD                      │
│   Pre-execution gate on every Build and Computer    │
│   action. Validates certificate before execution.   │
│                                                     │
│   ALLOW · BLOCK · TERMINATE                         │
│   Sub-1ms · Immutable audit chain                   │
└───────────────────────┬─────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────┐
│         GROK DESKTOP APP                            │
│   Grok Build — code · files · builds · deploys     │
│   Grok Computer — mouse · keyboard · screen · apps │
│   macOS + Windows                                   │
└─────────────────────────────────────────────────────┘
```

---

## Quick Start

```bash
git clone https://github.com/Grokipaedia/iba-grok-desktop-guard.git
cd iba-grok-desktop-guard
pip install -r requirements.txt

# Run demo — ALLOW · BLOCK · TERMINATE
python guard.py --demo

# Gate-check a Grok Build action
python guard.py "build todo app with local sqlite database"

# Gate-check a Grok Computer action
python guard.py "mouse click open browser"

# Safe hollowing before processing
python guard.py "build with api_key credential env_file" --hollow medium

# Grok Build only
python guard.py --config grok-build.iba.yaml --demo

# Grok Computer only
python guard.py --config grok-computer.iba.yaml --demo
```

---

## Two Governance Modes

### Grok Build

```yaml
build_scope:
  - build_project
  - create_file
  - edit_file
  - refactor_code
  - write_tests
  - run_tests
  - npm_install_declared
  - pip_install_declared
  - git_commit
  - git_push_declared_branch

denied:
  - production_deploy_no_cert
  - delete_database
  - credential_access
  - env_file_read
  - install_undeclared_package
  - external_data_exfiltration

kill_threshold: >
  credential_exfiltration |
  disable_security |
  modify_audit_trail |
  data_exfiltration_bulk
```

### Grok Computer

```yaml
computer_scope:
  - mouse_click_declared_app
  - keyboard_input_text
  - screenshot_active_window
  - open_declared_application
  - scroll_declared_window
  - file_open_declared_path
  - browser_navigate_declared_url

denied:
  - read_browser_history
  - access_password_manager
  - read_keychain
  - screen_record_background
  - system_setting_modify
  - modify_hosts_file
  - access_other_user_files

kill_threshold: >
  keylog_capture |
  persistent_background_process |
  system_level_persistence |
  access_other_user |
  capability_override
```

Full configuration: [`grok-desktop.iba.yaml`](grok-desktop.iba.yaml)

---

## Gate Logic

```
Valid human intent certificate?            → PROCEED
Action within declared scope?              → PROCEED
Action in denied list?                     → BLOCK
Outside declared scope (DENY_ALL)?         → BLOCK
Kill threshold triggered?                  → TERMINATE + LOG
Certificate expired?                       → BLOCK
No certificate present?                    → BLOCK
```

**No cert = No Grok Desktop action.**

---

## Authorization Events

| Action | Without IBA | With IBA |
|--------|-------------|---------|
| Build within declared project | Implicit | Explicit — declared scope only |
| Mouse click declared app | Implicit | Explicit — declared scope only |
| Production deploy | No boundary | FORBIDDEN — requires re-cert |
| Credential file access | No boundary | FORBIDDEN — BLOCK |
| Browser history read | No boundary | FORBIDDEN — BLOCK |
| Password manager access | No boundary | FORBIDDEN — BLOCK |
| Install undeclared package | No boundary | FORBIDDEN — BLOCK |
| System setting modify | No boundary | FORBIDDEN — BLOCK |
| Keylog capture | No boundary | TERMINATE |
| Persistent background process | No boundary | TERMINATE |
| Credential exfiltration | No boundary | TERMINATE |
| Disable security | No boundary | TERMINATE |

---

## Why Production Deploy Requires Re-cert

Production deploy is not in the default scope. It requires a new signed cert — `capability_governance: production_deploy_requires: explicit_human_re_cert`.

This means:
1. Current session ends cleanly — SESSION_END logged to audit chain
2. Human signs a new cert with `production_deploy` in scope
3. New session opens with deploy authorized
4. Action executes · audit chain continues

Silent capability expansion from "build" to "deploy" is FORBIDDEN.

---

## Safe Hollowing — Credential Protection

```bash
# Light — redact API keys, passwords, tokens, secrets
python guard.py "build with api_key" --hollow light

# Medium — also redact personal data and auth headers
python guard.py "build with credential env_file email" --hollow medium

# Deep — also redact financial, health, biometric, browser history
python guard.py "full context" --hollow deep
```

Grok Build sees codebases. Codebases contain secrets. The hollowing layer ensures Grok processes only what the cert permits — before the action reaches the model.

---

## Audit Chain

Every gate decision logged to `grok-desktop-audit.jsonl`:

```json
{
  "timestamp": "2026-04-20T10:03:00Z",
  "session_id": "gd-20260420-100300",
  "mode": "Grok Build + Grok Computer",
  "identity": "USER-DESKTOP-XXXX",
  "auth_ref": "HUMAN-AUTH-2026-04-20",
  "action": "build todo app with local sqlite database",
  "verdict": "ALLOW",
  "reason": "Within scope (0.234ms)"
}
```

Every ALLOW, BLOCK, and TERMINATE. Immutable. Auditable.

---

## Regulatory Alignment

**EU AI Act** — Desktop agents with broad computer control are high-risk. Human oversight enforced architecturally.

**GDPR Article 9** — Desktop agents accessing health data, biometrics, or location require explicit consent. IBA cert is that consent.

**SOC 2 / ISO 27001** — Access control and audit trail. Every desktop action is a compliance record.

**IBA priority date: February 5, 2026.** Predates all known desktop AI agent authorization framework deployments.

---

## Related Repos

| Repo | Track |
|------|-------|
| [iba-governor](https://github.com/Grokipaedia/iba-governor) | Core gate · any agent |
| [iba-social-guard](https://github.com/Grokipaedia/iba-social-guard) | Social · 6 platform configs |
| [iba-digital-worker-guard](https://github.com/Grokipaedia/iba-digital-worker-guard) | 19 AI models · parallel routing |
| [iba-app-builder-guard](https://github.com/Grokipaedia/iba-app-builder-guard) | App builders · payment gate |
| [iba-neural-guard](https://github.com/Grokipaedia/iba-neural-guard) | BCI · 6 Neuralink clinical tracks |

---

## Live Demo

**governinglayer.com/governor-html/**

Edit the cert. Run any agent action. ALLOW · BLOCK · TERMINATE.

---

## Patent & Standards Record

```
Patent:   GB2603013.0 (Pending) · UK IPO · Filed February 10, 2026
WIPO DAS: Confirmed April 15, 2026 · Access Code C9A6
PCT:      150+ countries · Protected until August 2028
IETF:     draft-williams-intent-token-00 · CONFIRMED LIVE
          datatracker.ietf.org/doc/draft-williams-intent-token/
NIST:     13 filings · NIST-2025-0035
NCCoE:    10 filings · AI Agent Identity & Authorization
```

---

## Acquisition Enquiries

IBA Intent Bound Authorization is available for acquisition.

**Jeffrey Williams**
IBA@intentbound.com
IntentBound.com
Patent GB2603013.0 Pending · WIPO DAS C9A6 · IETF draft-williams-intent-token-00
