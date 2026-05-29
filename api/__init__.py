"""
api/ — Flask Blueprints
Each file registers its own routes and is mounted in app.py.

  status_api.py  → /api/status
  fetch_api.py   → /api/fetch-real, /api/clear, /api/activity
  logs_api.py    → /api/stats, /api/days/<cat>, /api/logs/<cat>, /api/upload
  analyze_api.py → /api/analyze/*
  chat_api.py    → /api/chat, /api/chat/status, /api/chat/context
"""
