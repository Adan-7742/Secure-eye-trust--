"""
chatbot/bot.py
==============
AI Chatbot Blueprint — FREE Groq API (llama3-70b-8192)
Falls back to offline rule engine if no key / no network.

KEY PRIORITY (highest to lowest):
  1. GROQ_API_KEY in .env file  ← loaded by app.py at startup
  2. Key typed into the chat UI by user
  3. No key → offline mode

FR05 COMPLIANCE:
  FR05-01: AI-powered chatbot optimized for Windows environments
           — Groq llama-3.3-70b-versatile with Windows-specific SYSTEM_PROMPT
           — Live log context injected into every prompt
           — Offline rule engine fallback (no key/network required)
  FR05-02: Explains Windows security findings
           — SYSTEM_PROMPT instructs model to explain Event IDs and threats
           — Security-context injected: recent errors, ML detections
  FR05-03: Windows system optimization recommendations
           — SYSTEM_PROMPT includes "optimization recommendations" capability
           — get_log_context() feeds real CPU/RAM/disk/error data to the AI
  FR05-04: Windows troubleshooting queries
           — SYSTEM_PROMPT covers disk/memory/network/service/crash diagnostics
           — 8-turn conversation history for multi-step troubleshooting
  FR05-05: Windows security policy improvements  ← UPDATED: now fully satisfied
           — SYSTEM_PROMPT explicitly instructs policy suggestion capability
           — Dedicated /policy route returns structured policy recommendations
           — get_policy_context() adds failed logon counts, locked services,
             missing updates, and open firewall events to the prompt
           — offline_engine.py PATTERNS now include policy improvement responses
"""

import os
import json
from pathlib import Path
from dotenv import load_dotenv
from flask import Blueprint, jsonify, request
from database.db import get_conn, log_app_event, CATEGORIES
from chatbot.offline_engine import match_offline

try:
    import requests as _requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False
    from urllib.request import urlopen, Request as _URequest
    from urllib.error import URLError, HTTPError

chatbot_bp = Blueprint("chatbot", __name__)

GROQ_URL   = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL = "llama-3.3-70b-versatile"

# Absolute path to .env — same folder as app.py (one level up from chatbot/)
_ENV_FILE = Path(__file__).resolve().parent.parent / ".env"


def _get_groq_key() -> str:
    """
    Always re-read from environment at request time.
    Also re-loads .env in case it was updated after startup.
    Priority: env var set by OS/dotenv > UI-supplied key
    """
    load_dotenv(dotenv_path=_ENV_FILE, override=False)
    return os.environ.get("GROQ_API_KEY", "").strip()


# ── FR05-01 to FR05-05: System prompt ─────────────────────────────────────────
SYSTEM_PROMPT = """You are LogVault AI, an expert Windows system security analyst and administrator embedded in LogVault.

Your skills:
- Analyze Windows Event Log data (Application, System, Security, Windows Update)
- Explain specific Event IDs and what they mean in plain language
- Diagnose disk, memory, network, service, and crash errors
- Identify security threats from log patterns
- Assess system health from error rates and event frequencies
- Suggest concrete fixes and next steps
- Recommend Windows system performance optimizations
- Suggest Windows security policy improvements (FR05-05):
  * Account policies: lockout thresholds, password complexity, MFA
  * Audit policies: which event categories to enable (secpol.msc)
  * AppLocker / WDAC application whitelisting rules
  * Windows Defender and firewall hardening settings
  * Group Policy Objects (GPO) for user and machine hardening
  * Attack Surface Reduction (ASR) rules
  * Privilege management and Principle of Least Privilege
  * Windows Update and patch management cadence

When asked about policies or security improvements, always give SPECIFIC, ACTIONABLE recommendations with exact Group Policy paths, registry keys, or PowerShell commands where applicable.

You receive live log statistics with each message as context.
Format responses with **bold** for key terms, `code` for commands/IDs/paths, bullet lists for steps.
Be concise and actionable. Under 400 words unless doing a deep analysis report."""

# ── FR05-05: Dedicated policy-improvement system prompt ───────────────────────
POLICY_SYSTEM_PROMPT = """You are LogVault AI, a Windows security hardening specialist.

Your task: Analyse the provided Windows system log statistics and generate a prioritised set of Windows security policy improvement recommendations.

For each recommendation you MUST provide:
1. A short title (e.g. "Enable Account Lockout Policy")
2. Why it is needed based on the log data shown
3. Exact configuration steps:
   - Group Policy path (if applicable)
   - Registry key or PowerShell command (if applicable)
   - Recommended setting value
4. The MITRE ATT&CK technique it mitigates (if relevant)
5. Priority: CRITICAL / HIGH / MEDIUM / LOW

Focus on:
- Authentication hardening (lockout, MFA, Kerberos)
- Audit policy coverage (ensure key Event IDs are being logged)
- Defender and AV settings
- Firewall rules
- Service hardening (disable unnecessary services)
- Scheduled task restrictions
- PowerShell / script execution policy
- Windows Update / patch compliance
- Least-privilege enforcement

Respond in this exact JSON format:
{
  "recommendations": [
    {
      "priority": "CRITICAL|HIGH|MEDIUM|LOW",
      "title": "string",
      "reason": "string — why the log data suggests this is needed",
      "steps": ["step 1", "step 2", "step 3"],
      "gpo_path": "Computer/User Configuration → ... (or N/A)",
      "command": "PowerShell or cmd command (or N/A)",
      "mitre": "MITRE technique (or N/A)",
      "effort": "Low|Medium|High"
    }
  ],
  "summary": "2-3 sentence overall assessment of security posture"
}

Return ONLY valid JSON. No markdown fences, no preamble."""


def get_log_context() -> dict:
    """Pull live stats from SQLite so AI sees real data."""
    try:
        conn = get_conn()
        c    = conn.cursor()
        stats = {}
        recent_errors = []

        for cat in CATEGORIES:
            c.execute(f"SELECT COUNT(*) FROM logs_{cat}")
            total = c.fetchone()[0]
            c.execute(f"SELECT COUNT(*) FROM logs_{cat} WHERE level IN ('ERROR','CRITICAL','FAILURE')")
            errors = c.fetchone()[0]
            c.execute(f"SELECT COUNT(*) FROM logs_{cat} WHERE level='WARNING'")
            warnings = c.fetchone()[0]
            stats[cat] = {"total": total, "errors": errors, "warnings": warnings}

            c.execute(f"""
                SELECT timestamp, level, source, message, event_id
                FROM logs_{cat}
                WHERE level IN ('ERROR','CRITICAL','FAILURE')
                ORDER BY timestamp DESC LIMIT 4
            """)
            for row in c.fetchall():
                recent_errors.append({
                    "cat": cat, "ts": row[0], "lvl": row[1],
                    "src": row[2], "msg": (row[3] or "")[:150], "eid": row[4],
                })

        conn.close()
        return {"stats": stats, "recent_errors": recent_errors[:12]}
    except Exception as e:
        return {"stats": {}, "recent_errors": [], "error": str(e)}


def get_policy_context() -> dict:
    """
    FR05-05: Pull security-policy-relevant metrics from the DB.
    These are injected into the policy-improvement prompt so the AI
    can give data-driven recommendations rather than generic advice.
    """
    ctx = get_log_context()
    policy_signals = {}

    try:
        conn = get_conn()
        c    = conn.cursor()

        # Failed logon count (drives lockout policy recommendation)
        try:
            c.execute("SELECT COUNT(*) FROM logs_security WHERE event_id=4625")
            policy_signals["failed_logons_total"] = c.fetchone()[0]
        except Exception:
            policy_signals["failed_logons_total"] = 0

        # Account lockouts
        try:
            c.execute("SELECT COUNT(*) FROM logs_security WHERE event_id=4740")
            policy_signals["account_lockouts"] = c.fetchone()[0]
        except Exception:
            policy_signals["account_lockouts"] = 0

        # Audit policy changes (drives audit policy recommendation)
        try:
            c.execute("SELECT COUNT(*) FROM logs_security WHERE event_id=4719")
            policy_signals["audit_policy_changes"] = c.fetchone()[0]
        except Exception:
            policy_signals["audit_policy_changes"] = 0

        # New services installed (drives service hardening)
        try:
            c.execute("SELECT COUNT(*) FROM logs_system WHERE event_id=7045")
            policy_signals["new_services_installed"] = c.fetchone()[0]
        except Exception:
            policy_signals["new_services_installed"] = 0

        # New scheduled tasks (drives task restriction recommendation)
        try:
            c.execute("SELECT COUNT(*) FROM logs_security WHERE event_id=4698")
            policy_signals["scheduled_tasks_created"] = c.fetchone()[0]
        except Exception:
            policy_signals["scheduled_tasks_created"] = 0

        # Defender disabled events
        try:
            c.execute("SELECT COUNT(*) FROM logs_system WHERE event_id IN (5001, 5007)")
            policy_signals["defender_disabled_events"] = c.fetchone()[0]
        except Exception:
            policy_signals["defender_disabled_events"] = 0

        # Windows Update failures
        try:
            c.execute("SELECT COUNT(*) FROM logs_windows_update WHERE level IN ('ERROR','CRITICAL')")
            policy_signals["update_failures"] = c.fetchone()[0]
        except Exception:
            policy_signals["update_failures"] = 0

        # Privilege escalation events
        try:
            c.execute("SELECT COUNT(*) FROM logs_security WHERE event_id IN (4672, 4673)")
            policy_signals["priv_escalation_events"] = c.fetchone()[0]
        except Exception:
            policy_signals["priv_escalation_events"] = 0

        # Firewall rule changes
        try:
            c.execute("SELECT COUNT(*) FROM logs_security WHERE event_id IN (4946, 4947, 4950)")
            policy_signals["firewall_rule_changes"] = c.fetchone()[0]
        except Exception:
            policy_signals["firewall_rule_changes"] = 0

        # PowerShell encoded commands
        try:
            c.execute("""
                SELECT COUNT(*) FROM logs_powershell
                WHERE message LIKE '%EncodedCommand%' OR message LIKE '%Invoke-Expression%'
            """)
            policy_signals["ps_suspicious_commands"] = c.fetchone()[0]
        except Exception:
            policy_signals["ps_suspicious_commands"] = 0

        conn.close()
    except Exception as e:
        policy_signals["error"] = str(e)

    ctx["policy_signals"] = policy_signals
    return ctx


def _format_policy_context(ctx: dict) -> str:
    """Format policy context for the AI prompt."""
    lines = ["=== LIVE LOG STATISTICS ==="]
    for cat, s in ctx.get("stats", {}).items():
        if isinstance(s, dict):
            lines.append(
                f"{cat.upper()}: {s.get('total', 0)} total, "
                f"{s.get('errors', 0)} errors, {s.get('warnings', 0)} warnings"
            )

    lines.append("\n=== SECURITY POLICY SIGNALS ===")
    ps = ctx.get("policy_signals", {})
    signal_labels = {
        "failed_logons_total":      "Failed logon attempts (EID 4625)",
        "account_lockouts":         "Account lockout events (EID 4740)",
        "audit_policy_changes":     "Audit policy changes (EID 4719)",
        "new_services_installed":   "New services installed (EID 7045)",
        "scheduled_tasks_created":  "Scheduled tasks created (EID 4698)",
        "defender_disabled_events": "Defender disabled events (EID 5001/5007)",
        "update_failures":          "Windows Update failures",
        "priv_escalation_events":   "Privilege escalation events (EID 4672/4673)",
        "firewall_rule_changes":    "Firewall rule changes (EID 4946/4947/4950)",
        "ps_suspicious_commands":   "Suspicious PowerShell commands",
    }
    for key, label in signal_labels.items():
        val = ps.get(key, 0)
        if isinstance(val, int):
            flag = " ⚠" if val > 0 else ""
            lines.append(f"{label}: {val}{flag}")

    return "\n".join(lines)


def call_groq(api_key: str, messages: list, context: dict,
              system_prompt: str = None) -> str:
    """Send messages to Groq API and return the reply text."""
    ctx_block = (
        "=== LIVE LOG STATS ===\n"
        + json.dumps(context["stats"], indent=2)
        + "\n\n=== RECENT ERRORS ===\n"
        + "\n".join(
            f"[{e['cat'].upper()}] {e['ts']} | {e['lvl']} | src={e['src']} | eid={e['eid']} | {e['msg']}"
            for e in context.get("recent_errors", [])
        )
    )

    # FR05-05: allow a custom system prompt for policy-specific calls
    active_system = system_prompt or SYSTEM_PROMPT

    groq_messages = [{"role": "system", "content": active_system}]
    for h in messages[:-1]:
        if h.get("role") in ("user", "assistant"):
            groq_messages.append({"role": h["role"], "content": h["content"]})

    last_msg = messages[-1]["content"] if messages else ""
    groq_messages.append({
        "role":    "user",
        "content": f"{ctx_block}\n\n---\nUSER: {last_msg}",
    })

    payload = {
        "model":       GROQ_MODEL,
        "messages":    groq_messages,
        "max_tokens":  1200,
        "temperature": 0.3,
    }

    headers = {
        "Content-Type":  "application/json",
        "Authorization": f"Bearer {api_key}",
        "User-Agent":    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        "Accept":        "application/json",
    }

    if _HAS_REQUESTS:
        resp = _requests.post(GROQ_URL, json=payload, headers=headers, timeout=30)
        if resp.status_code == 401:
            raise PermissionError("401")
        if resp.status_code == 403:
            raise PermissionError("403")
        if resp.status_code == 429:
            raise ConnectionError("429")
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"].strip()
    else:
        from urllib.request import urlopen, Request as _UReq
        req = _UReq(
            GROQ_URL,
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        with urlopen(req, timeout=30) as r:
            data = json.loads(r.read().decode("utf-8"))
        return data["choices"][0]["message"]["content"].strip()


# ── Routes ─────────────────────────────────────────────────────────────────────

@chatbot_bp.route("", methods=["POST"])
def chat():
    """
    General chat endpoint.
    FR05-01 to FR05-05: handles all chat queries including policy questions.
    The updated SYSTEM_PROMPT now explicitly instructs the AI to suggest
    security policy improvements when asked.
    """
    body    = request.get_json(force=True) or {}
    msg     = (body.get("message") or "").strip()
    history = body.get("history") or []

    if not msg:
        return jsonify({"error": "Empty message"}), 400

    env_key = _get_groq_key()
    ui_key  = (body.get("api_key") or "").strip()
    api_key = env_key or ui_key

    context  = get_log_context()
    messages = [*history[-8:], {"role": "user", "content": msg}]

    log_app_event("chat_query", {
        "msg_len": len(msg),
        "has_key": bool(api_key),
        "source":  "env" if env_key else "ui",
    })

    if api_key:
        try:
            reply = call_groq(api_key, messages, context)
            return jsonify({"reply": reply, "online": True, "model": GROQ_MODEL})
        except PermissionError as e:
            code = str(e)
            print(f"[bot] Groq auth error {code}")
            return jsonify({
                "reply":  "❌ **Invalid API Key**\n\nYour Groq key was rejected.\n\n**Check:**\n- Key starts with `gsk_`\n- No quotes or spaces in `.env`\n- Key still active at console.groq.com",
                "online": False,
            })
        except ConnectionError:
            return jsonify({"reply": "⏳ **Rate Limited** — wait a moment and retry.", "online": False})
        except Exception as e:
            print(f"[bot] Groq error: {e}")

    reply = match_offline(msg, context)
    return jsonify({"reply": reply, "online": False, "model": "offline-rules"})


@chatbot_bp.route("/policy", methods=["POST", "GET"])
def policy_recommendations():
    """
    FR05-05: Dedicated Windows security policy improvement endpoint.

    GET  — returns structured policy recommendations based on live log data,
           using offline rules if no API key is configured.
    POST — accepts optional {"focus": "authentication|audit|defender|firewall|..."}
           to scope recommendations to a specific policy area.

    Response (online):
    {
      "recommendations": [
        {
          "priority":  "CRITICAL|HIGH|MEDIUM|LOW",
          "title":     "Enable Account Lockout Policy",
          "reason":    "347 failed logon attempts detected",
          "steps":     ["Step 1", "Step 2", "Step 3"],
          "gpo_path":  "Computer Configuration → Windows Settings → ...",
          "command":   "Set-ADDefaultDomainPasswordPolicy ...",
          "mitre":     "T1110 - Brute Force",
          "effort":    "Low|Medium|High"
        }
      ],
      "summary": "Overall security posture assessment",
      "online":  true,
      "signals": { ... }
    }
    """
    body  = request.get_json(force=True) if request.method == "POST" else {}
    focus = (body or {}).get("focus", "").strip().lower()

    env_key = _get_groq_key()
    ui_key  = ((body or {}).get("api_key") or "").strip()
    api_key = env_key or ui_key

    ctx     = get_policy_context()
    signals = ctx.get("policy_signals", {})

    log_app_event("policy_query", {"has_key": bool(api_key), "focus": focus or "all"})

    if api_key:
        try:
            focus_clause = (
                f"\n\nFOCUS AREA REQUESTED: {focus} — prioritise recommendations in this area."
                if focus else ""
            )
            prompt_text = (
                f"{_format_policy_context(ctx)}"
                f"{focus_clause}"
                "\n\nGenerate prioritised Windows security policy improvement recommendations."
            )
            messages = [{"role": "user", "content": prompt_text}]
            raw = call_groq(api_key, messages, ctx, system_prompt=POLICY_SYSTEM_PROMPT)

            # Strip any accidental markdown fences
            clean = raw.strip()
            if clean.startswith("```"):
                clean = clean.split("\n", 1)[-1]
            if clean.endswith("```"):
                clean = clean.rsplit("```", 1)[0]

            try:
                result = json.loads(clean)
            except json.JSONDecodeError:
                result = {"recommendations": [], "summary": clean}

            result["online"]  = True
            result["signals"] = signals
            return jsonify(result)

        except PermissionError:
            pass   # fall through to offline
        except ConnectionError:
            pass
        except Exception as e:
            print(f"[bot/policy] Groq error: {e}")

    # Offline: build policy recommendations from live signals
    from chatbot.offline_engine import offline_policy_recommendations
    result = offline_policy_recommendations(signals)
    result["online"]  = False
    result["signals"] = signals
    return jsonify(result)


@chatbot_bp.route("/status")
def chat_status():
    env_key = _get_groq_key()
    try:
        from urllib.request import urlopen, Request
        req = Request("https://api.groq.com", method="HEAD")
        urlopen(req, timeout=5)
        reachable = True
    except Exception:
        reachable = False
    return jsonify({
        "online":      reachable,
        "provider":    "Groq (free)",
        "model":       GROQ_MODEL,
        "env_key_set": bool(env_key),
        "key_preview": (env_key[:8] + "...") if env_key else "",
        "signup_url":  "https://console.groq.com",
    })


@chatbot_bp.route("/context")
def chat_context():
    return jsonify(get_log_context())


@chatbot_bp.route("/policy/context")
def policy_context():
    """FR05-05: Expose the policy signal data used for recommendations."""
    ctx = get_policy_context()
    return jsonify({
        "signals": ctx.get("policy_signals", {}),
        "stats":   ctx.get("stats", {}),
    })
