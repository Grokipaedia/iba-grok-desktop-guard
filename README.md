# iba-grok-desktop-guard

**Grok on your desktop. Human intent required.**

Grok Build + Grok Computer are dropping together as a unified desktop app for macOS and Windows.

This tool adds real cryptographic governance on top.

Wrap every Grok desktop action (build, computer control, file access, long-running workflows) with a signed **IBA Intent Certificate** so the agent stays within your exact approved rules.

## Features
- Requires IBA-signed intent before any desktop action or build
- Enforces scope across Grok Build and Grok Computer
- Hard-denies unauthorized file access, system changes, or persistent workflows
- Optional safe hollowing for high-risk operations
- Works with the unified Grok desktop app (macOS + Windows)

## Patent & Filings
- **Patent Pending**: GB2603013.0 (filed 5 Feb 2026, PCT route open — 150+ countries)
- **NIST Docket**: NIST-2025-0035 (13 IBA filings)
- **NCCoE Filings**: 10 submissions on AI agent authorization

## Quick Start
```bash
git clone https://github.com/Grokipaedia/iba-grok-desktop-guard.git
cd iba-grok-desktop-guard
pip install -r requirements.txt
python guard.py "build a full-stack todo app with local database" --hollow medium
