"""
services/rag_service.py
=======================
RAG (Retrieval-Augmented Generation) Service for Secure Eye Trust+

Architecture:
    Windows Event Logs
         ↓
    Parser / Threat Detector
         ↓
    RAG Service  ←── this file
       ├── Embed query log       (sentence-transformers or TF-IDF fallback)
       ├── Search FAISS index
       ├── Retrieve incidents/docs
         ↓
    Groq LLM API
         ↓
    Structured threat analysis
       ├── Threat severity
       ├── MITRE ATT&CK mapping
       ├── Possible attack chain
       └── Recommended actions

Usage:
    from services.rag_service import get_rag_service
    svc = get_rag_service()
    result = svc.analyze_log(log_text, context_logs=[...])
"""

import os
import json
import time
import math
import hashlib
import threading
import logging
from datetime import datetime
from typing import Optional

import requests

logger = logging.getLogger(__name__)

# ── MITRE ATT&CK knowledge base (built-in, no external fetch needed) ──────────

MITRE_KNOWLEDGE_BASE = [
    # ── Initial Access ────────────────────────────────────────────────────────
    {
        "id": "T1078",
        "tactic": "Initial Access / Persistence",
        "technique": "Valid Accounts",
        "keywords": ["4624", "4625", "4648", "logon", "login", "authentication", "credential"],
        "description": "Adversaries use valid credentials to gain access. EID 4624=success, 4625=failure (brute force), 4648=explicit credentials.",
        "indicators": ["Multiple 4625 failures followed by 4624", "Off-hours logons", "New logon from unusual IP"],
        "severity": "HIGH",
    },
    {
        "id": "T1110",
        "tactic": "Credential Access",
        "technique": "Brute Force",
        "keywords": ["4625", "failed logon", "login fail", "wrong password", "account lockout", "4740"],
        "description": "Repeated failed authentication attempts. EID 4625 repeated rapidly = brute force. EID 4740 = account locked out.",
        "indicators": [">5 EID 4625 within 1 hour from same source", "EID 4740 lockout", "Multiple user targets"],
        "severity": "CRITICAL",
    },
    {
        "id": "T1548",
        "tactic": "Privilege Escalation",
        "technique": "Abuse Elevation Control Mechanism",
        "keywords": ["4672", "4673", "special privilege", "elevated", "admin", "runas", "UAC"],
        "description": "EID 4672 = special privileges assigned. EID 4673 = privileged service called. Indicates privilege escalation attempt.",
        "indicators": ["EID 4672 for non-admin account", "Unusual process requesting 4673", "UAC bypass"],
        "severity": "HIGH",
    },
    {
        "id": "T1053",
        "tactic": "Execution / Persistence",
        "technique": "Scheduled Task/Job",
        "keywords": ["4698", "4699", "4700", "4701", "4702", "schtask", "task created", "scheduled task"],
        "description": "EID 4698=task created, 4699=deleted, 4700=enabled, 4701=disabled, 4702=updated. Attackers use tasks for persistence.",
        "indicators": ["EID 4698 for unknown task", "Task running as SYSTEM", "Task with encoded command"],
        "severity": "MEDIUM",
    },
    {
        "id": "T1136",
        "tactic": "Persistence",
        "technique": "Create Account",
        "keywords": ["4720", "4728", "user created", "new account", "added admin", "net user", "net localgroup"],
        "description": "EID 4720=user account created, EID 4728=user added to security-enabled global group (Administrators).",
        "indicators": ["EID 4720 outside business hours", "Immediately followed by EID 4728", "New admin account"],
        "severity": "HIGH",
    },
    {
        "id": "T1562",
        "tactic": "Defense Evasion",
        "technique": "Impair Defenses",
        "keywords": ["4719", "audit policy", "defender", "5001", "firewall disabled", "logging disabled"],
        "description": "EID 4719=audit policy changed (attacker hiding tracks). EID 5001=Defender real-time disabled. Impairs detection capability.",
        "indicators": ["EID 4719 audit subcategory disabled", "Defender service stopped", "Event log cleared"],
        "severity": "CRITICAL",
    },
    {
        "id": "T1005",
        "tactic": "Collection",
        "technique": "Data from Local System",
        "keywords": ["4663", "file access", "read file", "copy file", "data collection"],
        "description": "EID 4663=object access. Adversaries search and collect data from local file systems before exfiltration.",
        "indicators": ["High volume EID 4663 on sensitive directories", "Access to credential stores", "Bulk file reads"],
        "severity": "MEDIUM",
    },
    {
        "id": "T1021",
        "tactic": "Lateral Movement",
        "technique": "Remote Services",
        "keywords": ["4624 type 3", "network logon", "SMB", "RDP", "4648", "pass the hash", "psexec"],
        "description": "Network logons (type 3) indicate lateral movement. EID 4648 with remote target suggests pass-the-hash or explicit credential use.",
        "indicators": ["EID 4624 logon type 3 from unusual source", "Multiple hosts authenticating in sequence", "EID 4648 with NTLM"],
        "severity": "HIGH",
    },
    {
        "id": "T1003",
        "tactic": "Credential Access",
        "technique": "OS Credential Dumping",
        "keywords": ["mimikatz", "lsass", "4616", "sekurlsa", "credential dumping", "ntds", "sam database"],
        "description": "Attackers dump credentials from LSASS memory (Mimikatz), SAM, or NTDS.dit. Windows Defender often flags this.",
        "indicators": ["Defender alert for Mimikatz", "LSASS memory access by non-system process", "EID 4616 system time change"],
        "severity": "CRITICAL",
    },
    {
        "id": "T1059",
        "tactic": "Execution",
        "technique": "Command and Scripting Interpreter",
        "keywords": ["powershell", "cmd.exe", "wscript", "cscript", "4688", "process create", "encoded command", "-enc"],
        "description": "EID 4688=new process created. PowerShell with encoded commands (-enc) or obfuscation is common attacker technique.",
        "indicators": ["EID 4688 powershell with -enc flag", "Cmd.exe spawned by Office process", "WScript running VBS"],
        "severity": "HIGH",
    },
    {
        "id": "T1543",
        "tactic": "Persistence",
        "technique": "Create or Modify System Process",
        "keywords": ["7045", "new service", "service installed", "7000", "7001", "7009", "7023", "7031", "7034"],
        "description": "EID 7045=new service installed. Attackers install malicious services for persistence. EID 7034=service crashed unexpectedly.",
        "indicators": ["EID 7045 for unknown service", "Service with suspicious binary path", "Service running as SYSTEM"],
        "severity": "HIGH",
    },
    {
        "id": "T1486",
        "tactic": "Impact",
        "technique": "Data Encrypted for Impact (Ransomware)",
        "keywords": ["ransomware", "encrypted", "extension changed", "vss delete", "shadow copy", "wbadmin"],
        "description": "Ransomware encrypts files and deletes shadow copies. Look for mass file renames, VSS deletion commands.",
        "indicators": ["Mass file extension changes", "vssadmin delete shadows", "wbadmin delete catalog", "Defender ransomware alert"],
        "severity": "CRITICAL",
    },
    {
        "id": "T1070",
        "tactic": "Defense Evasion",
        "technique": "Indicator Removal",
        "keywords": ["1102", "event log cleared", "log cleared", "wevtutil cl", "clear-eventlog"],
        "description": "EID 1102=security log cleared. Attackers clear logs to cover tracks. This is always suspicious.",
        "indicators": ["EID 1102 any time", "wevtutil cl command", "Multiple logs cleared in sequence"],
        "severity": "CRITICAL",
    },
    {
        "id": "T1190",
        "tactic": "Initial Access",
        "technique": "Exploit Public-Facing Application",
        "keywords": ["application error", "access violation", "1000", "crash", "exploit", "buffer overflow", "heap"],
        "description": "EID 1000=application crash. Repeated crashes of web-facing apps may indicate exploitation attempts.",
        "indicators": ["EID 1000 for IIS/Apache/web app", "Access violation in network-facing service", "Repeated crashes of same process"],
        "severity": "HIGH",
    },
    {
        "id": "T1499",
        "tactic": "Impact",
        "technique": "Endpoint Denial of Service",
        "keywords": ["kernel power", "6008", "41", "unexpected shutdown", "BSOD", "bugcheck", "critical process died"],
        "description": "EID 6008=unexpected shutdown, EID 41=kernel power failure. May indicate DoS, hardware failure, or BSOD from driver exploit.",
        "indicators": ["EID 41 without prior shutdown event", "EID 6008 repeated", "Kernel panic / BSOD"],
        "severity": "HIGH",
    },
    {
        "id": "T1112",
        "tactic": "Defense Evasion / Persistence",
        "technique": "Modify Registry",
        "keywords": ["4657", "registry", "regedit", "reg add", "hklm", "hkcu", "run key"],
        "description": "EID 4657=registry value modified. Attackers use Run keys (HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run) for persistence.",
        "indicators": ["EID 4657 on Run/RunOnce keys", "Registry modification by unknown process", "Autorun key changes"],
        "severity": "HIGH",
    },
    # ── Hardware / Stability ──────────────────────────────────────────────────
    {
        "id": "SYS-001",
        "tactic": "System Health",
        "technique": "Disk Hardware Error",
        "keywords": ["disk error", "bad sector", "ntfs", "i/o error", "11", "7", "disk", "hard drive failure"],
        "description": "EID 11/7=disk error in System log. Bad sectors indicate imminent hardware failure. Data loss risk.",
        "indicators": ["EID 11 repeated on same disk", "NTFS errors", "Increasing bad sector count"],
        "severity": "HIGH",
    },
    {
        "id": "SYS-002",
        "tactic": "System Health",
        "technique": "Memory Corruption",
        "keywords": ["memory corrupt", "bad pool", "pool corrupt", "IRQL", "memory parity"],
        "description": "Memory corruption can indicate faulty RAM, driver bugs, or rootkit activity corrupting kernel structures.",
        "indicators": ["BSOD with memory-related stop code", "Bad pool caller errors", "ECC errors"],
        "severity": "HIGH",
    },
]

# Build a fast lookup: keyword → list of MITRE entries
_KEYWORD_INDEX: dict[str, list] = {}
for _entry in MITRE_KNOWLEDGE_BASE:
    for _kw in _entry["keywords"]:
        _kw_lower = _kw.lower()
        _KEYWORD_INDEX.setdefault(_kw_lower, []).append(_entry)


# ── Lightweight TF-IDF vector (no heavy ML deps required) ────────────────────

def _tokenize(text: str) -> list[str]:
    """Simple word tokenizer, lowercased, alphanumeric only."""
    import re
    return re.findall(r"[a-z0-9]+", text.lower())


def _tfidf_vector(text: str, vocab: list[str]) -> list[float]:
    """Build a normalized TF vector for a given text over the vocab."""
    tokens = _tokenize(text)
    counts: dict[str, int] = {}
    for t in tokens:
        counts[t] = counts.get(t, 0) + 1
    total = max(len(tokens), 1)
    vec = [counts.get(w, 0) / total for w in vocab]
    norm = math.sqrt(sum(v * v for v in vec)) or 1.0
    return [v / norm for v in vec]


def _cosine_sim(a: list[float], b: list[float]) -> float:
    return sum(x * y for x, y in zip(a, b))


# ── FAISS-lite: pure-Python vector store (fallback when faiss-cpu not present) ─

class PythonVectorStore:
    """
    Lightweight in-memory vector store using cosine similarity.
    Used as a fallback when faiss-cpu is not installed.
    """

    def __init__(self):
        self._docs:    list[dict]        = []
        self._vecs:    list[list[float]] = []
        self._vocab:   list[str]         = []
        self._lock     = threading.Lock()
        self._built    = False

    def _rebuild_vocab(self):
        all_tokens: set[str] = set()
        for doc in self._docs:
            all_tokens.update(_tokenize(doc.get("text", "")))
        self._vocab = sorted(all_tokens)

    def add(self, docs: list[dict]):
        """Add documents {text, metadata} to the store."""
        with self._lock:
            self._docs.extend(docs)
            self._built = False

    def _ensure_built(self):
        if self._built:
            return
        self._rebuild_vocab()
        self._vecs = [_tfidf_vector(d.get("text", ""), self._vocab) for d in self._docs]
        self._built = True

    def search(self, query: str, k: int = 4) -> list[dict]:
        """Return top-k most similar documents."""
        with self._lock:
            if not self._docs:
                return []
            self._ensure_built()
            q_vec = _tfidf_vector(query, self._vocab)
            scored = [
                (_cosine_sim(q_vec, v), i)
                for i, v in enumerate(self._vecs)
            ]
            scored.sort(reverse=True)
            results = []
            for score, idx in scored[:k]:
                doc = dict(self._docs[idx])
                doc["_score"] = round(score, 4)
                results.append(doc)
            return results

    @property
    def count(self) -> int:
        return len(self._docs)


# ── Try to use real FAISS if available ────────────────────────────────────────

class FAISSVectorStore:
    """
    FAISS-backed vector store. Requires: pip install faiss-cpu sentence-transformers
    Falls back gracefully if not available.
    """

    def __init__(self, dim: int = 384):
        import faiss
        import numpy as np
        self._faiss  = faiss
        self._np     = np
        self._dim    = dim
        self._index  = faiss.IndexFlatIP(dim)   # Inner product = cosine if normalized
        self._docs:  list[dict] = []
        self._lock   = threading.Lock()

    def _embed(self, texts: list[str]):
        from sentence_transformers import SentenceTransformer
        if not hasattr(self, "_model"):
            self._model = SentenceTransformer("all-MiniLM-L6-v2")
        vecs = self._model.encode(texts, normalize_embeddings=True)
        return self._np.array(vecs, dtype="float32")

    def add(self, docs: list[dict]):
        texts = [d.get("text", "") for d in docs]
        vecs  = self._embed(texts)
        with self._lock:
            self._index.add(vecs)
            self._docs.extend(docs)

    def search(self, query: str, k: int = 4) -> list[dict]:
        with self._lock:
            if self._index.ntotal == 0:
                return []
        q_vec = self._embed([query])
        D, I  = self._index.search(q_vec, min(k, self._index.ntotal))
        results = []
        for score, idx in zip(D[0], I[0]):
            if idx < 0:
                continue
            doc = dict(self._docs[idx])
            doc["_score"] = float(score)
            results.append(doc)
        return results

    @property
    def count(self) -> int:
        with self._lock:
            return self._index.ntotal


def _build_vector_store():
    """Try FAISS first, fall back to Python store."""
    try:
        import faiss                   # noqa: F401
        import sentence_transformers   # noqa: F401
        store = FAISSVectorStore()
        logger.info("[RAG] Using FAISS + sentence-transformers vector store")
        return store
    except ImportError:
        store = PythonVectorStore()
        logger.info("[RAG] Using Python TF-IDF vector store (install faiss-cpu + sentence-transformers for better results)")
        return store


# ── RAG Service ───────────────────────────────────────────────────────────────

class RAGService:
    """
    Main RAG service that:
    1. Indexes Windows event logs + MITRE knowledge base
    2. Embeds incoming log queries
    3. Retrieves relevant context via FAISS / TF-IDF
    4. Calls Groq LLM with structured prompt
    5. Returns structured threat analysis
    """

    GROQ_URL   = "https://api.groq.com/openai/v1/chat/completions"
    GROQ_MODEL = "llama-3.3-70b-versatile"

    def __init__(self):
        self._store  = _build_vector_store()
        self._lock   = threading.Lock()
        self._seeded = False
        self._seed_mitre()

    # ── Seeding ───────────────────────────────────────────────────────────────

    def _seed_mitre(self):
        """Load MITRE ATT&CK knowledge base into the vector store."""
        docs = []
        for entry in MITRE_KNOWLEDGE_BASE:
            text = (
                f"{entry['technique']} ({entry['id']}) — {entry['tactic']}. "
                f"{entry['description']} "
                f"Indicators: {'; '.join(entry['indicators'])}. "
                f"Keywords: {', '.join(entry['keywords'])}."
            )
            docs.append({
                "text":     text,
                "type":     "mitre",
                "id":       entry["id"],
                "tactic":   entry["tactic"],
                "technique":entry["technique"],
                "severity": entry["severity"],
                "description": entry["description"],
                "indicators":  entry["indicators"],
            })
        self._store.add(docs)
        self._seeded = True
        logger.info(f"[RAG] Seeded {len(docs)} MITRE ATT&CK entries")

    def index_logs(self, logs: list):
        """
        Index a batch of Windows event log entries so they can be retrieved
        as historical incident context.

        Accepts both dicts {message, source, level, timestamp, event_id}
        and plain strings (treated as the full log line).
        """
        docs = []
        for log in logs:
            # Handle plain strings
            if isinstance(log, str):
                text = log[:500]
                docs.append({
                    "text":      text,
                    "type":      "incident",
                    "source":    "unknown",
                    "level":     "INFO",
                    "event_id":  "",
                    "timestamp": "",
                    "message":   text[:300],
                })
                continue

            # Handle dicts
            msg  = str(log.get("message", "") or log.get("msg", ""))[:500]
            src  = str(log.get("source", "Unknown"))
            lvl  = str(log.get("level", "INFO"))
            ts   = str(log.get("timestamp", log.get("ts", "")))
            eid  = str(log.get("event_id", log.get("eid", "")))

            text = f"[{lvl}] {src} EventID={eid} at {ts}: {msg}"
            docs.append({
                "text":      text,
                "type":      "incident",
                "source":    src,
                "level":     lvl,
                "event_id":  eid,
                "timestamp": ts,
                "message":   msg[:300],
            })
        if docs:
            self._store.add(docs)
            logger.info(f"[RAG] Indexed {len(docs)} log entries (total: {self._store.count})")

    def index_logs_from_db(self, limit: int = 500):
        """Pull recent ERROR/CRITICAL/FAILURE logs from the existing SQLite DB."""
        try:
            from database.db import get_conn, CATEGORIES
            conn = get_conn()
            c    = conn.cursor()
            logs = []
            for cat in CATEGORIES:
                tbl = f"logs_{cat}"
                try:
                    c.execute(f"""
                        SELECT COALESCE(message,''), source, level, timestamp, event_id
                        FROM {tbl}
                        WHERE level IN ('ERROR','CRITICAL','FAILURE','WARNING')
                        ORDER BY id DESC LIMIT ?
                    """, (limit // max(len(CATEGORIES), 1),))
                    for row in c.fetchall():
                        logs.append({
                            "message":   row[0],
                            "source":    row[1] or "Unknown",
                            "level":     row[2] or "INFO",
                            "timestamp": row[3] or "",
                            "event_id":  str(row[4] or ""),
                        })
                except Exception:
                    pass
            conn.close()
            if logs:
                self.index_logs(logs)
            return len(logs)
        except Exception as e:
            logger.warning(f"[RAG] DB index failed: {e}")
            return 0

    # ── Retrieval ─────────────────────────────────────────────────────────────

    def retrieve(self, query: str, k: int = 5) -> list[dict]:
        """Retrieve top-k relevant documents for the query."""
        results = self._store.search(query, k=k)
        return results

    def _keyword_match(self, log_text: str) -> list[dict]:
        """Fast keyword-based MITRE lookup (runs in parallel with vector search)."""
        log_lower  = log_text.lower()
        matched:   dict[str, dict] = {}
        for kw, entries in _KEYWORD_INDEX.items():
            if kw in log_lower:
                for entry in entries:
                    matched[entry["id"]] = entry
        # Sort by severity weight
        sev_w = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        return sorted(matched.values(), key=lambda e: sev_w.get(e["severity"], 0), reverse=True)

    # ── Groq LLM call ─────────────────────────────────────────────────────────

    def _call_groq(self, system_prompt: str, user_prompt: str, max_tokens: int = 800) -> str:
        api_key = os.environ.get("GROQ_API_KEY", "").strip()
        if not api_key:
            raise RuntimeError("GROQ_API_KEY not set in environment / .env file")

        resp = requests.post(
            self.GROQ_URL,
            json={
                "model":       self.GROQ_MODEL,
                "messages":    [
                    {"role": "system", "content": system_prompt},
                    {"role": "user",   "content": user_prompt},
                ],
                "max_tokens":  max_tokens,
                "temperature": 0.2,
            },
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type":  "application/json",
            },
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"].strip()

    # ── Main analysis ─────────────────────────────────────────────────────────

    def analyze_log(
        self,
        log: str | dict,
        context_logs: Optional[list] = None,
        k: int = 4,
    ) -> dict:
        """
        Full RAG pipeline:
          1. Normalise log to string
          2. Keyword-match MITRE entries
          3. Vector-search for similar incidents
          4. Build prompt with retrieved context
          5. Call Groq LLM
          6. Parse + return structured result

        Returns:
            {
              "ok": True,
              "severity": "CRITICAL|HIGH|MEDIUM|LOW",
              "mitre": [{"id":..., "tactic":..., "technique":...}],
              "attack_description": str,
              "recommended_actions": [str],
              "retrieved_context": [...],   # what the RAG found
              "raw_analysis": str,          # full LLM text
              "log": str,                   # the analysed log
              "timestamp": str,
            }
        """
        t0 = time.time()

        # -- Normalise log to string
        if isinstance(log, dict):
            log_str = (
                f"[{log.get('level','?')}] EventID={log.get('event_id','')} "
                f"Source={log.get('source','')} "
                f"at {log.get('timestamp', log.get('ts',''))} — "
                f"{log.get('message', log.get('msg',''))}"
            )
        else:
            log_str = str(log)

        query = log_str[:600]

        # -- Step 1: keyword-based fast MITRE match
        kw_matches = self._keyword_match(query)

        # -- Step 2: vector retrieval
        retrieved = self.retrieve(query, k=k)

        # -- Step 3: build context string for LLM
        ctx_parts = []

        if kw_matches:
            ctx_parts.append("=== MITRE ATT&CK KEYWORD MATCHES ===")
            for m in kw_matches[:4]:
                ctx_parts.append(
                    f"• {m['id']} — {m['technique']} ({m['tactic']}) [{m['severity']}]\n"
                    f"  {m['description']}\n"
                    f"  Indicators: {'; '.join(m['indicators'][:2])}"
                )

        incident_docs = [r for r in retrieved if r.get("type") == "incident"]
        if incident_docs:
            ctx_parts.append("\n=== SIMILAR HISTORICAL INCIDENTS ===")
            for doc in incident_docs[:3]:
                ctx_parts.append(f"• [{doc.get('level','?')}] {doc.get('source','')} EID={doc.get('event_id','')} — {doc.get('message','')[:120]}")

        if context_logs:
            ctx_parts.append("\n=== SURROUNDING LOG CONTEXT ===")
            for cl in context_logs[:5]:
                if isinstance(cl, dict):
                    ctx_parts.append(f"• [{cl.get('level','?')}] {cl.get('source','')} — {cl.get('message','')[:100]}")
                else:
                    ctx_parts.append(f"• {str(cl)[:120]}")

        retrieved_context = "\n".join(ctx_parts) if ctx_parts else "No additional context retrieved."

        # -- Step 4: LLM prompt
        system_prompt = (
            "You are a senior Windows cybersecurity analyst with deep expertise in "
            "Windows Event IDs, MITRE ATT&CK, threat hunting, and incident response. "
            "You receive a Windows event log entry plus retrieved context from a knowledge base. "
            "Respond ONLY with a valid JSON object — no markdown, no code blocks, no extra text. "
            "The JSON must have exactly these keys: "
            "severity (string: CRITICAL/HIGH/MEDIUM/LOW/INFO), "
            "mitre (array of {id, tactic, technique}), "
            "attack_description (string: 2-3 sentences explaining what is happening), "
            "recommended_actions (array of 3-5 specific action strings). "
            "Base your analysis on the actual log content and the retrieved context provided."
        )

        user_prompt = (
            f"Relevant incidents and MITRE knowledge:\n{retrieved_context}\n\n"
            f"Analyze this Windows event log:\n{query}\n\n"
            "Provide:\n"
            "1. Threat severity (CRITICAL / HIGH / MEDIUM / LOW / INFO)\n"
            "2. MITRE ATT&CK mapping (technique IDs + names)\n"
            "3. What attack or event is likely happening\n"
            "4. Recommended actions\n\n"
            "Respond with ONLY the JSON object."
        )

        # -- Step 5: call Groq
        try:
            raw = self._call_groq(system_prompt, user_prompt)
        except Exception as e:
            # Graceful degradation: return keyword-based result without LLM
            return self._fallback_result(log_str, kw_matches, retrieved, str(e))

        # -- Step 6: parse JSON
        try:
            import re
            # Strip any accidental markdown fences
            clean = re.sub(r"```(?:json)?|```", "", raw).strip()
            parsed = json.loads(clean)
        except Exception:
            parsed = {
                "severity":            self._infer_severity(kw_matches),
                "mitre":               [{"id": m["id"], "tactic": m["tactic"], "technique": m["technique"]} for m in kw_matches[:3]],
                "attack_description":  raw[:400],
                "recommended_actions": ["Review the flagged log entry", "Check related events in the same timeframe"],
            }

        elapsed = round(time.time() - t0, 2)

        return {
            "ok":                True,
            "severity":          parsed.get("severity", "MEDIUM"),
            "mitre":             parsed.get("mitre", []),
            "attack_description":parsed.get("attack_description", ""),
            "recommended_actions":parsed.get("recommended_actions", []),
            "retrieved_context": retrieved_context,
            "raw_analysis":      raw,
            "log":               log_str[:400],
            "elapsed_s":         elapsed,
            "timestamp":         datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "retrieval_stats": {
                "keyword_matches": len(kw_matches),
                "vector_results":  len(retrieved),
                "store_size":      self._store.count,
            },
        }

    def _infer_severity(self, kw_matches: list) -> str:
        if not kw_matches:
            return "LOW"
        sev_w = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        top = max(kw_matches, key=lambda m: sev_w.get(m.get("severity", "LOW"), 0))
        return top.get("severity", "MEDIUM")

    def _fallback_result(self, log_str: str, kw_matches: list, retrieved: list, error: str) -> dict:
        """Return a keyword-only result when the LLM call fails."""
        mitre = [
            {"id": m["id"], "tactic": m["tactic"], "technique": m["technique"]}
            for m in kw_matches[:3]
        ]
        severity = self._infer_severity(kw_matches)
        actions  = []
        for m in kw_matches[:2]:
            actions.extend(m.get("indicators", [])[:1])
        actions = actions or ["Review the flagged event manually", "Check surrounding log entries"]

        return {
            "ok":                True,
            "severity":          severity,
            "mitre":             mitre,
            "attack_description":f"Keyword-based analysis (LLM unavailable: {error}). "
                                 f"Matched MITRE techniques: {', '.join(m['technique'] for m in kw_matches[:3]) or 'none'}.",
            "recommended_actions":actions,
            "retrieved_context": "",
            "raw_analysis":      f"[LLM error: {error}]",
            "log":               log_str[:400],
            "elapsed_s":         0,
            "timestamp":         datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "retrieval_stats": {
                "keyword_matches": len(kw_matches),
                "vector_results":  len(retrieved),
                "store_size":      self._store.count,
            },
        }

    def bulk_analyze(self, logs: list, k: int = 3) -> list[dict]:
        """Analyze multiple logs. Indexes them first so they provide context to each other."""
        self.index_logs(logs)
        results = []
        for log in logs:
            results.append(self.analyze_log(log, k=k))
        return results

    @property
    def stats(self) -> dict:
        return {
            "store_size":   self._store.count,
            "store_type":   type(self._store).__name__,
            "mitre_seeded": self._seeded,
            "groq_key_set": bool(os.environ.get("GROQ_API_KEY")),
        }


# ── Singleton accessor ────────────────────────────────────────────────────────

_rag_instance: Optional[RAGService] = None
_rag_lock = threading.Lock()


def get_rag_service() -> RAGService:
    """Get or create the singleton RAG service instance."""
    global _rag_instance
    if _rag_instance is None:
        with _rag_lock:
            if _rag_instance is None:
                _rag_instance = RAGService()
                # Background: pull recent bad logs from DB into the index
                def _warm():
                    try:
                        n = _rag_instance.index_logs_from_db(limit=400)
                        logger.info(f"[RAG] Warmed index with {n} DB logs")
                    except Exception as e:
                        logger.warning(f"[RAG] Warm-up failed: {e}")
                threading.Thread(target=_warm, daemon=True, name="rag_warmup").start()
    return _rag_instance
