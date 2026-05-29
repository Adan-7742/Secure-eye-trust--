"""
api/chat_api.py
================
Blueprint: /api/chat, /api/chat/status, /api/chat/context

AI Chatbot using GROQ API (FREE — no cost, no credit card needed).
Groq provides llama3-8b-instruct with a generous free tier.

HOW TO GET YOUR FREE GROQ API KEY:
    1. Go to https://console.groq.com
    2. Sign up for free (Google/GitHub login)
    3. Click "API Keys" → "Create API Key"
    4. Copy the key (starts with gsk_...)
    5. Enter it in the chat UI → ⚙ API Key

FREE TIER LIMITS (as of 2026):
    - 30 requests/minute
    - 14,400 requests/day
    - llama3-8b-8192 model (fast, smart)
    - No credit card required

HOW DATA FLOWS IN CHAT:
    1. User types message in browser
    2. static/js/chat.js sends POST /api/chat with {message, history, api_key}
    3. chat_api.py fetches live log stats from database (context)
    4. Builds prompt: SYSTEM PROMPT + LOG CONTEXT + message history
    5. Sends to Groq API (or falls back to offline rule engine)
    6. Returns {reply, online, model} to browser
    7. chat.js renders the markdown response

OFFLINE FALLBACK:
    If no API key or no internet → chatbot/offline_engine.py handles the query
    with rule-based pattern matching + event ID lookup.
"""

import json
import os
from urllib.request import urlopen, Request
from urllib.error import URLError
from flask import Blueprint, jsonify, request
from database.db import get_conn, LOG_CATEGORIES
from chatbot.offline_engine import match_offline
from chatbot.context_builder import build_context
from utils.logger import get_logger
from datetime import datetime

chat_bp = Blueprint("chat", __name__)
log     = get_logger("chat_api")

# ── Groq API config ────────────────────────────────────────────────────────────
GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL   = "llama3-8b-8192"    # fast, smart, FREE on Groq
ENV_API_KEY  = os.environ.get("GROQ_API_KEY", "")

# ── System prompt for the AI ──────────────────────────────────────────────────
SYSTEM_PROMPT = """You are LogVault AI, an expert Windows system log analyst.

You are embedded in LogVault — an encrypted Windows Event Log analysis dashboard.

Your expertise:
- Windows Event Log analysis (Application, System, Security, Windows Update)
- Security incident detection and response
- Disk, memory, service, and hardware diagnostics
- Event ID interpretation and troubleshooting
- System health assessment from log patterns

You receive live log statistics as context in every message.
Be concise, technical, and actionable.
Use markdown: **bold** for key terms, `code` for Event IDs/commands, bullet lists.
Maximum 350 words per response unless doing a deep analysis."""


def call_groq(api_key: str, messages: list, context: dict) -> dict:
    """
    Call Groq's OpenAI-compatible API.
    Groq uses the same request format as OpenAI — just a different base URL.
    Returns {"reply": str, "online": True, "model": str}
    """
    ctx_text = _format_context(context)

    # Inject context into first user message
    msgs = list(messages)
    if msgs and msgs[0]["role"] == "user":
        msgs[0] = {
            "role":    "user",
            "content": f"{ctx_text}\n\n---\nUSER: {msgs[0]['content']}"
        }

    payload = json.dumps({
        "model":       GROQ_MODEL,
        "max_tokens":  1024,
        "temperature": 0.3,
        "messages":    [{"role": "system", "content": SYSTEM_PROMPT}] + msgs,
    }).encode("utf-8")

    req = Request(
        GROQ_API_URL,
        data=payload,
        headers={
            "Content-Type":  "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        method="POST"
    )

    with urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read().decode("utf-8"))

    reply = data["choices"][0]["message"]["content"].strip()
    return {"reply": reply, "online": True, "model": GROQ_MODEL}


def _format_context(context: dict) -> str:
    """Format live log stats as a readable context block for the AI."""
    lines = ["=== LIVE LOG STATISTICS ==="]
    for cat, s in context.get("stats", {}).items():
        if isinstance(s, dict):
            lines.append(
                f"{cat.upper()}: {s.get('total',0)} total, "
                f"{s.get('errors',0)} errors, {s.get('warnings',0)} warnings"
            )

    lines.append("\n=== RECENT ERRORS (last 10) ===")
    for e in context.get("recent_errors", [])[:10]:
        lines.append(
            f"[{e.get('category','?').upper()}] {e.get('timestamp','')} | "
            f"{e.get('level','')} | src={e.get('source','')} | "
            f"eid={e.get('event_id','')} | {str(e.get('message',''))[:150]}"
        )

    lines.append("\n=== ML THREAT DETECTIONS ===")
    for d in context.get("ml_detections", [])[:3]:
        lines.append(f"[{d.get('severity','?')}] {d.get('name','?')} — {d.get('description','')[:100]}")

    return "\n".join(lines)


# ── Routes ─────────────────────────────────────────────────────────────────────

@chat_bp.route("/chat", methods=["POST"])
def chat():
    body    = request.get_json(force=True) or {}
    user_msg = (body.get("message") or "").strip()
    history  = body.get("history") or []
    api_key  = body.get("api_key") or ENV_API_KEY

    if not user_msg:
        return jsonify({"error": "Empty message"}), 400

    # Fetch live context from DB
    context = build_context()

    # Build Groq message history (last 8 turns)
    messages = []
    for h in history[-8:]:
        if h.get("role") in ("user", "assistant") and h.get("content"):
            messages.append({"role": h["role"], "content": h["content"]})
    messages.append({"role": "user", "content": user_msg})

    # Try Groq API first
    if api_key:
        try:
            result = call_groq(api_key, messages, context)
            _save_chat(user_msg, result["reply"], result["model"], True)
            return jsonify({
                "reply":   result["reply"],
                "online":  True,
                "model":   result["model"],
                "context": {
                    "total_events": sum(v.get("total",0) for v in context["stats"].values() if isinstance(v, dict)),
                    "total_errors": sum(v.get("errors",0) for v in context["stats"].values() if isinstance(v, dict)),
                }
            })
        except URLError:
            pass   # no internet → fall through to offline
        except Exception as e:
            err = str(e)
            log.error(f"Groq API error: {err}")
            if "401" in err or "invalid_api_key" in err.lower():
                return jsonify({"reply": "❌ **Invalid API Key**\n\nYour Groq API key was rejected.\n1. Go to https://console.groq.com\n2. Create a new API key\n3. Click ⚙ API Key in the chat panel and paste it.", "online": False})
            if "429" in err:
                return jsonify({"reply": "⏳ **Rate Limited**\n\nGroq free tier: 30 requests/minute. Please wait a moment.", "online": False})

    # Offline fallback
    reply = match_offline(user_msg, context)
    _save_chat(user_msg, reply, "offline", False)
    return jsonify({"reply": reply, "online": False, "model": "offline-rules"})


@chat_bp.route("/chat/status")
def chat_status():
    """Check if Groq API is reachable."""
    try:
        req = Request("https://api.groq.com", method="HEAD")
        urlopen(req, timeout=5)
        online = True
    except Exception:
        online = False
    return jsonify({
        "online":       online,
        "provider":     "Groq (free)",
        "model":        GROQ_MODEL,
        "env_key_set":  bool(ENV_API_KEY),
        "signup_url":   "https://console.groq.com",
    })


@chat_bp.route("/chat/context")
def chat_context():
    """Return live log stats used as AI context."""
    return jsonify(build_context())


def _save_chat(user_msg: str, reply: str, model: str, online: bool):
    """Persist chat messages to the database."""
    try:
        conn = get_conn()
        now  = datetime.now().isoformat()
        conn.execute(
            "INSERT INTO chat_sessions (role,content,model,online,created_at) VALUES (?,?,?,?,?)",
            ("user", user_msg, model, int(online), now)
        )
        conn.execute(
            "INSERT INTO chat_sessions (role,content,model,online,created_at) VALUES (?,?,?,?,?)",
            ("assistant", reply, model, int(online), now)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        log.warning(f"Failed to save chat: {e}")
