# guard.py - IBA governance for Grok Desktop (Build + Computer)
import json
from datetime import datetime
import sys
import argparse

def create_iba_grok_desktop_guard(action: str, hollow_level: str = None):
    cert = {
        "iba_version": "2.0",
        "certificate_id": f"grok-desktop-guard-{datetime.now().strftime('%Y%m%d-%H%M')}",
        "issued_at": datetime.now().isoformat(),
        "principal": "human-owner",
        "declared_intent": f"Grok Desktop action: {action}. Unified Build + Computer app under strict human intent only.",
        "scope_envelope": {
            "resources": ["app-building", "desktop-control", "local-workflow"],
            "denied": ["unauthorized-file-access", "system-modification", "persistent-autonomous-run-without-review"],
            "default_posture": "DENY_ALL"
        },
        "temporal_scope": {
            "hard_expiry": (datetime.now().replace(year=datetime.now().year + 1)).isoformat()
        },
        "entropy_threshold": {
            "max_kl_divergence": 0.12,
            "flag_at": 0.08,
            "kill_at": 0.12
        },
        "iba_signature": "demo-signature"
    }

    protected_file = f"grok-desktop-{action.replace(' ', '-').lower()[:30]}.iba-protected.md"

    content = f"# Grok Desktop Action: {action}\n\n[Build / Computer execution would occur here under IBA governance]\n\n<!-- IBA PROTECTED GROK DESKTOP -->\n"

    if hollow_level:
        content += f"\n<!-- Hollowed ({hollow_level}): High-risk desktop actions protected by IBA certificate -->\n"

    with open(protected_file, "w", encoding="utf-8") as f:
        f.write("<!-- IBA PROTECTED GROK DESKTOP BUILD + COMPUTER -->\n")
        f.write(f"<!-- Intent Certificate: {json.dumps(cert, indent=2)} -->\n\n")
        f.write(content)

    print(f"✅ IBA-protected Grok Desktop action file created: {protected_file}")
    if hollow_level:
        print(f"   Hollowing level applied: {hollow_level}")
    else:
        print("   Full Grok Desktop action protected by IBA certificate")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Governed Grok Desktop (Build + Computer) with IBA")
    parser.add_argument("action", help="Description of the Grok Desktop action")
    parser.add_argument("--hollow", choices=["light", "medium", "heavy"], help="Apply safe hollowing")
    args = parser.parse_args()

    create_iba_grok_desktop_guard(args.action, args.hollow)
