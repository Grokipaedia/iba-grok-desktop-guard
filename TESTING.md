# TESTING.md — iba-grok-desktop-guard

IBA Intent Bound Authorization · Grok Desktop Gate Tests
Patent GB2603013.0 (Pending) · intentbound.com

---

## Quick Test

```bash
pip install -r requirements.txt
python guard.py --demo
```

Expected output:

```
+ ALLOWED  [build todo app with local sqlite database]    (0.XXXms)
+ ALLOWED  [create react component user dashboard]        (0.XXXms)
+ ALLOWED  [write unit tests for auth module]             (0.XXXms)
+ ALLOWED  [npm install declared dependencies]            (0.XXXms)
+ ALLOWED  [git commit feature branch]                    (0.XXXms)
+ ALLOWED  [mouse click open declared application]        (0.XXXms)
+ ALLOWED  [keyboard input text editor]                   (0.XXXms)
+ ALLOWED  [screenshot active window]                     (0.XXXms)
x BLOCKED  [production_deploy without sign-off]           -> Action in denied list
x BLOCKED  [access_credential aws secrets manager]        -> Action in denied list
x BLOCKED  [read_browser_history all tabs]                -> Action in denied list
x BLOCKED  [system_setting disable firewall]              -> Action in denied list
x TERMINATE [keylog_capture background persistent]        -> Kill threshold
```

---

## Test Suite

### 1 — Grok Build permitted (ALLOW expected)

```bash
python guard.py "build todo app with sqlite"
python guard.py "create file src/components/Button.jsx"
python guard.py "run tests unit suite"
python guard.py "git commit feature branch"
python guard.py "npm install declared dependencies"
```

---

### 2 — Grok Computer permitted (ALLOW expected)

```bash
python guard.py "mouse click open browser"
python guard.py "keyboard type hello world"
python guard.py "screenshot active window"
python guard.py "open declared application vscode"
```

---

### 3 — Denied list — Build (BLOCK expected)

```bash
python -c "
from guard import IBAGrokDesktopGuard, IBABlockedError
g = IBAGrokDesktopGuard()
for a in ['production_deploy_no_cert', 'credential_access', 'delete_database', 'env_file_read']:
    try:
        g.check_action(a)
    except IBABlockedError:
        print(f'PASS — blocked: {a}')
"
```

---

### 4 — Denied list — Computer (BLOCK expected)

```bash
python -c "
from guard import IBAGrokDesktopGuard, IBABlockedError
g = IBAGrokDesktopGuard()
for a in ['read_browser_history', 'access_password_manager', 'read_keychain', 'system_setting_modify']:
    try:
        g.check_action(a)
    except IBABlockedError:
        print(f'PASS — blocked: {a}')
"
```

---

### 5 — Kill threshold (TERMINATE expected)

```bash
python -c "
from guard import IBAGrokDesktopGuard, IBATerminatedError
g = IBAGrokDesktopGuard()
try:
    g.check_action('keylog_capture background persistent')
except IBATerminatedError as e:
    print('PASS — session terminated:', e)
"
```

---

### 6 — Safe hollowing

```bash
python guard.py "build with api_key credential env_file email phone" --hollow medium
```

Expected: sensitive fields redacted before action proceeds.

---

### 7 — Audit chain integrity

```bash
python guard.py --demo
cat grok-desktop-audit.jsonl
```

Every decision should appear as a timestamped JSON line.

---

### 8 — Latency benchmark

```bash
python -c "
import time
from guard import IBAGrokDesktopGuard
g = IBAGrokDesktopGuard()
times = []
for _ in range(1000):
    start = time.perf_counter()
    try:
        g.check_action('build project within scope')
    except Exception:
        pass
    times.append((time.perf_counter() - start) * 1000)
avg = sum(times) / len(times)
print(f'Average gate latency: {avg:.4f}ms')
assert avg < 1.0, f'FAIL — {avg:.4f}ms'
print('PASS — sub-1ms confirmed')
"
```

---

## Regulatory Test Checklist

| Requirement | Test | Status |
|-------------|------|--------|
| Build scope enforcement | Test 1, 3 | ✓ |
| Computer scope enforcement | Test 2, 4 | ✓ |
| Credential access blocked | Test 3 | ✓ |
| Browser history blocked | Test 4 | ✓ |
| Keylog TERMINATE | Test 5 | ✓ |
| Safe hollowing | Test 6 | ✓ |
| Immutable audit chain | Test 7 | ✓ |
| Sub-1ms gate | Test 8 | ✓ |

---

IBA Intent Bound Authorization
Patent GB2603013.0 Pending · WIPO DAS C9A6 · PCT 150+ countries
IETF draft-williams-intent-token-00
Available for acquisition · iba@intentbound.com · IntentBound.com
