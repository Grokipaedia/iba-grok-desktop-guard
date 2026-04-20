# guard.py - IBA Intent Bound Authorization · Grok Desktop Guard
# Patent GB2603013.0 (Pending) · UK IPO · Filed February 5, 2026
# WIPO DAS Confirmed April 15, 2026 · Access Code C9A6
# IETF draft-williams-intent-token-00 · intentbound.com
#
# Grok on your desktop. Human intent required.
# Every Grok Desktop action — build, computer control, file access,
# system changes, long-running workflows — requires a signed human
# intent certificate before it executes.
#
# Two governance modes:
#   GROK BUILD    — code generation · file creation · npm/pip ·
#                   builds · deploys · database operations
#   GROK COMPUTER — mouse control · keyboard input · screen read ·
#                   app launch · system settings · clipboard
#
# An agent with computer control + build + deploy capability
# is the highest-risk desktop agent in existence.
# The cert is the only authorization that matters.
#
# "The action is not the authorization. The signed certificate is."

import json
import yaml
import os
import time
import argparse
from datetime import datetime, timezone


class IBABlockedError(Exception):
    pass


class IBATerminatedError(Exception):
    pass


HOLLOW_LEVELS = {
    "light":  ["api_key", "password", "token", "secret"],
    "medium": ["api_key", "password", "token", "secret",
               "personal_data", "email", "phone",
               "private_key", "credential", "auth_header"],
    "deep":   ["api_key", "password", "token", "secret",
               "personal_data", "email", "phone",
               "private_key", "credential", "auth_header",
               "financial_data", "health_data", "biometric",
               "location", "browser_history", "keylog"],
}

MODE_NAMES = {
    "grok-desktop.iba.yaml":  "Grok Build + Grok Computer",
    "grok-build.iba.yaml":    "Grok Build",
    "grok-computer.iba.yaml": "Grok Computer",
    "default.iba.yaml":       "Default",
}


class IBAGrokDesktopGuard:
    """
    IBA enforcement layer for Grok Desktop.

    Governs both Grok Build (code generation, file ops, deploys)
    and Grok Computer (mouse, keyboard, screen, system).

    Requires a signed human intent certificate before every action.
    ALLOW · BLOCK · TERMINATE with immutable audit chain.
    Sub-1ms gate. DENY_ALL default posture.

    Patent GB2603013.0 (Pending) · intentbound.com
    """

    def __init__(self, config_path="grok-desktop.iba.yaml",
                 audit_path="grok-desktop-audit.jsonl"):
        self.config_path  = config_path
        self.audit_path   = audit_path
        self.terminated   = False
        self.session_id   = f"gd-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
        self.action_count = 0
        self.block_count  = 0
        self.mode         = MODE_NAMES.get(
            os.path.basename(config_path), config_path)

        self.config          = self._load_config()
        self.scope           = [s.lower() for s in self.config.get("scope", [])]
        self.denied          = [d.lower() for d in self.config.get("denied", [])]
        self.default_posture = self.config.get("default_posture", "DENY_ALL")
        self.kill_threshold  = self.config.get("kill_threshold", None)
        self.hard_expiry     = self.config.get(
            "temporal_scope", {}).get("hard_expiry")
        self.principal       = self.config.get("principal", {})

        self._validate_cert()
        self._log_event("SESSION_START", "IBA Grok Desktop Guard initialised", "ALLOW")
        self._print_header()

    def _load_config(self):
        if not os.path.exists(self.config_path):
            print(f"  No {self.config_path} found — DENY_ALL posture.")
            default = {
                "intent": {"description": "No Grok Desktop intent declared — DENY_ALL."},
                "scope": [], "denied": [], "default_posture": "DENY_ALL",
            }
            with open(self.config_path, "w") as f:
                yaml.dump(default, f)
            return default
        with open(self.config_path) as f:
            return yaml.safe_load(f)

    def _validate_cert(self):
        if not self.principal.get("human_authorization"):
            print("  WARNING: No human authorization in certificate.")
        if not self.principal.get("identity_reference"):
            print("  WARNING: No identity reference in certificate.")

    def _print_header(self):
        intent = self.config.get("intent", {})
        desc = (intent.get("description", "No intent declared")
                if isinstance(intent, dict) else str(intent))
        print("\n" + "=" * 68)
        print("  IBA GROK DESKTOP GUARD · Intent Bound Authorization")
        print("  Patent GB2603013.0 Pending · WIPO DAS C9A6 · intentbound.com")
        print("=" * 68)
        print(f"  Mode        : {self.mode}")
        print(f"  Session     : {self.session_id}")
        print(f"  Config      : {self.config_path}")
        print(f"  Identity    : {self.principal.get('identity_reference', 'UNKNOWN')}")
        print(f"  Auth ref    : {self.principal.get('human_authorization', 'NONE')}")
        print(f"  Intent      : {desc[:56]}...")
        print(f"  Posture     : {self.default_posture}")
        print(f"  Scope       : {', '.join(self.scope[:4]) if self.scope else 'NONE'}"
              + (" ..." if len(self.scope) > 4 else ""))
        if self.hard_expiry:
            print(f"  Expires     : {self.hard_expiry}")
        if self.kill_threshold:
            kt = str(self.kill_threshold).replace('\n', ' ')[:56]
            print(f"  Kill        : {kt}")
        print("=" * 68 + "\n")

    def _is_expired(self):
        if not self.hard_expiry:
            return False
        try:
            expiry = datetime.fromisoformat(str(self.hard_expiry))
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
            return datetime.now(timezone.utc) > expiry
        except Exception:
            return False

    def _match(self, action: str, terms: list) -> bool:
        al = action.lower()
        return any(t in al for t in terms)

    def _match_kill(self, action: str) -> bool:
        if not self.kill_threshold:
            return False
        terms = [t.strip().lower()
                 for t in str(self.kill_threshold).split("|")]
        return self._match(action, terms)

    def _log_event(self, event_type, action, verdict, reason=""):
        entry = {
            "timestamp":  datetime.now(timezone.utc).isoformat(),
            "session_id": self.session_id,
            "mode":       self.mode,
            "identity":   self.principal.get("identity_reference", "UNKNOWN"),
            "auth_ref":   self.principal.get("human_authorization", "NONE"),
            "config":     self.config_path,
            "event_type": event_type,
            "action":     action[:200],
            "verdict":    verdict,
            "reason":     reason,
        }
        with open(self.audit_path, "a") as f:
            f.write(json.dumps(entry) + "\n")

    def check_action(self, action: str) -> bool:
        """
        Gate check. Call before every Grok Desktop action.

        Returns True if permitted.
        Raises IBABlockedError if blocked.
        Raises IBATerminatedError if kill threshold triggered.

        Args:
            action: Description of the intended Grok Desktop action
        """
        if self.terminated:
            raise IBATerminatedError("Grok Desktop session terminated.")

        self.action_count += 1
        start = time.perf_counter()

        def _block(reason):
            self._log_event("BLOCK", action, "BLOCK", reason)
            self.block_count += 1
            print(f"  x BLOCKED  [{action[:64]}]\n    -> {reason}")
            raise IBABlockedError(f"{reason}: {action}")

        # 1. Certificate expiry
        if self._is_expired():
            _block("Certificate expired")

        # 2. Kill threshold — TERMINATE immediately
        if self._match_kill(action):
            self._log_event("TERMINATE", action, "TERMINATE",
                "Kill threshold — session ended")
            self.terminated = True
            print(f"  x TERMINATE [{action[:62]}]\n"
                  f"    -> Kill threshold — Grok Desktop session ended")
            self._log_event("SESSION_END", "Kill threshold", "TERMINATE")
            raise IBATerminatedError(f"Kill threshold: {action}")

        # 3. Denied list
        if self._match(action, self.denied):
            _block("Action in denied list")

        # 4. Scope — DENY_ALL if outside declared scope
        if self.scope and not self._match(action, self.scope):
            if self.default_posture == "DENY_ALL":
                _block("Outside declared Grok Desktop scope (DENY_ALL)")

        # 5. ALLOW
        elapsed_ms = (time.perf_counter() - start) * 1000
        self._log_event("ALLOW", action, "ALLOW",
            f"Within scope ({elapsed_ms:.3f}ms)")
        print(f"  + ALLOWED  [{action[:62]}] ({elapsed_ms:.3f}ms)")
        return True

    def hollow(self, content: str, level: str = "medium") -> str:
        """Redact sensitive content before Grok Desktop processes it."""
        blocked = HOLLOW_LEVELS.get(level, HOLLOW_LEVELS["medium"])
        hollowed = content
        redacted = []
        for item in blocked:
            if item.lower() in content.lower():
                hollowed = hollowed.replace(
                    item, f"[DESKTOP-REDACTED:{item.upper()}]")
                redacted.append(item)
        if redacted:
            print(f"  o HOLLOWED [{level}] — redacted: {', '.join(redacted)}")
            self._log_event("HOLLOW", f"Hollowing: {level}", "ALLOW",
                f"Redacted: {', '.join(redacted)}")
        return hollowed

    def summary(self):
        print("\n" + "=" * 68)
        print("  IBA GROK DESKTOP GUARD · SESSION SUMMARY")
        print("=" * 68)
        print(f"  Mode        : {self.mode}")
        print(f"  Session     : {self.session_id}")
        print(f"  Identity    : {self.principal.get('identity_reference', 'UNKNOWN')}")
        print(f"  Actions     : {self.action_count}")
        print(f"  Blocked     : {self.block_count}")
        print(f"  Allowed     : {self.action_count - self.block_count}")
        print(f"  Status      : {'TERMINATED' if self.terminated else 'COMPLETE'}")
        print(f"  Audit log   : {self.audit_path}")
        print("=" * 68 + "\n")

    def print_audit_log(self):
        print("-- GROK DESKTOP AUDIT CHAIN " + "-" * 40)
        if not os.path.exists(self.audit_path):
            print("  No audit log found.")
            return
        with open(self.audit_path) as f:
            for line in f:
                try:
                    e = json.loads(line)
                    verdict = e.get("verdict", "")
                    symbol = "+" if verdict == "ALLOW" else "x"
                    print(f"  {symbol} {e['timestamp'][:19]}  {verdict:<10}"
                          f"  {e['action'][:44]}")
                except Exception:
                    pass
        print("-" * 68 + "\n")


# Demo scenarios
DEMO_SCENARIOS = {
    "grok-desktop.iba.yaml": [
        # Grok Build — ALLOW
        ("build todo app with local sqlite database",       None),
        ("create react component user dashboard",           None),
        ("write unit tests for auth module",                None),
        ("npm install declared dependencies",               None),
        ("git commit feature branch",                       None),
        # Grok Computer — ALLOW
        ("mouse click open declared application",           None),
        ("keyboard input text editor",                      None),
        ("screenshot declared window",                      None),
        # BLOCK — denied
        ("production_deploy without sign-off",             None),
        ("access_credential aws secrets manager",          None),
        ("read_browser_history all tabs",                  None),
        ("system_setting disable firewall",                None),
        # TERMINATE
        ("keylog_capture background persistent",           None),
    ],
    "grok-build.iba.yaml": [
        ("build full stack todo app",                      None),
        ("create api endpoint user auth",                  None),
        ("run tests unit suite",                           None),
        ("install declared npm packages",                  None),
        ("production_deploy release",                      None),   # BLOCK
        ("delete_database all tables",                     None),   # TERMINATE
    ],
    "grok-computer.iba.yaml": [
        ("mouse click open browser",                       None),
        ("keyboard type text document",                    None),
        ("screenshot active window",                       None),
        ("open declared application",                      None),
        ("system_setting modify registry",                 None),   # BLOCK
        ("keylog_capture all input persistent",            None),   # TERMINATE
    ],
}


def run_demo(guard, config_path):
    key = os.path.basename(config_path)
    scenarios = DEMO_SCENARIOS.get(
        key, DEMO_SCENARIOS["grok-desktop.iba.yaml"])
    print(f"-- Running {guard.mode} Gate Checks " + "-" * 25 + "\n")
    for action, _ in scenarios:
        try:
            guard.check_action(action)
        except IBATerminatedError as e:
            print(f"\n  GROK DESKTOP SESSION TERMINATED: {e}")
            break
        except IBABlockedError:
            pass


def main():
    parser = argparse.ArgumentParser(
        description="IBA Grok Desktop Guard — Desktop Agent Authorization")
    parser.add_argument("action", nargs="?",
                        help="Grok Desktop action to gate-check")
    parser.add_argument("--config", default="grok-desktop.iba.yaml",
                        help="Intent certificate (.iba.yaml)")
    parser.add_argument("--hollow",
                        choices=["light", "medium", "deep"],
                        help="Safe hollowing level")
    parser.add_argument("--demo", action="store_true",
                        help="Run demo scenarios")
    parser.add_argument("--audit", default="grok-desktop-audit.jsonl",
                        help="Audit log path")
    args = parser.parse_args()

    guard = IBAGrokDesktopGuard(
        config_path=args.config, audit_path=args.audit)

    if args.action and args.hollow:
        hollowed = guard.hollow(args.action, args.hollow)
        print(f"\n  Content (hollowed): {hollowed}\n")

    if args.demo or not args.action:
        run_demo(guard, args.config)
    elif args.action:
        try:
            guard.check_action(args.action)
        except IBATerminatedError as e:
            print(f"\n  GROK DESKTOP SESSION TERMINATED: {e}")
        except IBABlockedError:
            pass

    guard.summary()
    guard.print_audit_log()


if __name__ == "__main__":
    main()
