# Re-export so callers can do:
#   from core.event_collector import fetch_all_logs, WIN32_AVAILABLE
from .collector import fetch_all_logs, WIN32_AVAILABLE, read_channel
