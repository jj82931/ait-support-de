import os

try:
    from supabase import create_client
except Exception:  # pragma: no cover
    create_client = None


def get_supabase_client():
    url = os.getenv("SUPABASE_URL")
    key = os.getenv("SUPABASE_SERVICE_ROLE_KEY") or os.getenv("SUPABASE_ANON_KEY")
    if not url or not key or create_client is None:
        return None
    return create_client(url, key)
