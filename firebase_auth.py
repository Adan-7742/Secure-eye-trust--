"""
firebase_auth.py — Secure Eye Trust+
Firebase Authentication integration.
- @gmail.com only
- Password never stored locally (Firebase bcrypt internally)
- Silent webcam capture after 2 wrong attempts
"""
import os, re, requests
from flask import session

FIREBASE_AUTH_URL = "https://identitytoolkit.googleapis.com/v1/accounts"

def _cfg():
    return {
        "apiKey":      os.environ.get("FIREBASE_API_KEY", ""),
        "projectId":   os.environ.get("FIREBASE_PROJECT_ID", ""),
        "databaseURL": os.environ.get("FIREBASE_DATABASE_URL", ""),
    }

def firebase_configured() -> bool:
    c = _cfg()
    return bool(c["apiKey"] and c["projectId"])

def is_valid_email(email: str) -> bool:
    if not email: return False
    return bool(re.match(r'^[a-zA-Z0-9._%+\-]+@gmail\.com$', email.strip().lower()))

def _friendly_error(code: str) -> str:
    MAP = {
        "EMAIL_EXISTS":                "This email is already registered.",
        "EMAIL_NOT_FOUND":             "Invalid email or password.",
        "INVALID_PASSWORD":            "Invalid email or password.",
        "INVALID_LOGIN_CREDENTIALS":   "Invalid email or password.",
        "USER_DISABLED":               "This account has been disabled.",
        "TOO_MANY_ATTEMPTS_TRY_LATER": "Too many failed attempts. Try again later.",
        "WEAK_PASSWORD":               "Password must be at least 6 characters.",
        "INVALID_EMAIL":               "Invalid email address.",
        "OPERATION_NOT_ALLOWED":       "Email/password auth is not enabled in Firebase.",
        "MISSING_PASSWORD":            "Please enter a password.",
    }
    for k, v in MAP.items():
        if k in code: return v
    return "Invalid email or password."  # generic — never leak internals

def firebase_register(email: str, password: str) -> dict:
    key = _cfg()["apiKey"]
    if not key: return {"ok": False, "error": "Firebase not configured"}
    try:
        r = requests.post(
            f"{FIREBASE_AUTH_URL}:signUp?key={key}",
            json={"email": email, "password": password, "returnSecureToken": True},
            timeout=10
        )
        d = r.json()
        if r.status_code == 200 and "idToken" in d:
            _save_profile(d.get("localId",""), email, d.get("idToken",""))
            return {"ok": True, "uid": d.get("localId",""), "email": d.get("email",""), "idToken": d.get("idToken","")}
        return {"ok": False, "error": _friendly_error(d.get("error",{}).get("message",""))}
    except requests.exceptions.Timeout:
        return {"ok": False, "error": "Connection timeout — check your internet."}
    except Exception as e:
        return {"ok": False, "error": "Registration failed. Try again."}

def firebase_login(email: str, password: str) -> dict:
    key = _cfg()["apiKey"]
    if not key: return {"ok": False, "error": "Firebase not configured"}
    try:
        r = requests.post(
            f"{FIREBASE_AUTH_URL}:signInWithPassword?key={key}",
            json={"email": email, "password": password, "returnSecureToken": True},
            timeout=10
        )
        d = r.json()
        if r.status_code == 200 and "idToken" in d:
            return {"ok": True, "uid": d.get("localId",""), "email": d.get("email",""), "idToken": d.get("idToken","")}
        return {"ok": False, "error": _friendly_error(d.get("error",{}).get("message",""))}
    except requests.exceptions.Timeout:
        return {"ok": False, "error": "Connection timeout — check your internet."}
    except Exception:
        return {"ok": False, "error": "Sign in failed. Try again."}

def firebase_reset_password(email: str) -> dict:
    key = _cfg()["apiKey"]
    try:
        r = requests.post(
            f"{FIREBASE_AUTH_URL}:sendOobCode?key={key}",
            json={"requestType": "PASSWORD_RESET", "email": email},
            timeout=10
        )
        d = r.json()
        if r.status_code == 200: return {"ok": True}
        return {"ok": False, "error": _friendly_error(d.get("error",{}).get("message","Failed"))}
    except Exception:
        return {"ok": False, "error": "Could not send reset email. Try again."}

def _save_profile(uid: str, email: str, id_token: str):
    db = _cfg()["databaseURL"].rstrip("/")
    if not db or not uid: return
    from datetime import datetime
    try:
        requests.put(
            f"{db}/users/{uid}.json?auth={id_token}",
            json={"email": email, "created_at": datetime.now().isoformat(),
                  "app": "Secure Eye Trust+", "role": "admin"},
            timeout=8
        )
    except Exception:
        pass

def set_firebase_session(uid: str, email: str, id_token: str):
    import secrets
    from datetime import datetime
    session["authenticated"] = True
    session["uid"]            = uid
    session["email"]          = email
    session["username"]       = email.split("@")[0]
    session["id_token"]       = id_token
    session["login_time"]     = datetime.now().isoformat()
    session["session_id"]     = secrets.token_hex(16)
