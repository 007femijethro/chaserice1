# db.py
import os
from sqlalchemy import create_engine

def pick_driver() -> str | None:
    """Return 'psycopg' (v3) or 'psycopg2' if installed, else None."""
    try:
        import psycopg  # psycopg v3
        return "psycopg"
    except Exception:
        pass
    try:
        import psycopg2  # psycopg2-binary
        return "psycopg2"
    except Exception:
        pass
    return None

def normalize_database_url(raw_url: str, driver: str | None) -> str:
    """
    Normalize DATABASE_URL for SQLAlchemy:
    - postgres:// -> postgresql://
    - Only add +<driver> if we actually have that driver importable
    - Enforce sslmode=require for hosted PG (Render)
    """
    if not raw_url:
        return ""

    # 1) Upgrade scheme
    if raw_url.startswith("postgres://"):
        raw_url = "postgresql://" + raw_url[len("postgres://"):]

    # 2) If it's a PG URL and no driver suffix is present, add the one we *have*
    if raw_url.startswith("postgresql://") and "+psycopg" not in raw_url and "+psycopg2" not in raw_url:
        if driver in ("psycopg", "psycopg2"):
            raw_url = raw_url.replace("postgresql://", f"postgresql+{driver}://", 1)

    # 3) Ensure SSL for hosted Postgres (safe no-op locally)
    if "sslmode=" not in raw_url:
        sep = "&" if "?" in raw_url else "?"
        raw_url = f"{raw_url}{sep}sslmode=require"

    return raw_url

raw = os.environ.get("DATABASE_URL", "").strip()
driver = pick_driver()
db_url = normalize_database_url(raw, driver)

if db_url:
    engine = create_engine(db_url, pool_pre_ping=True, future=True)
else:
    # Fallback to SQLite locally (no DATABASE_URL set)
    engine = create_engine("sqlite:///database.db", future=True)

# Optional: quick sanity log
try:
    print(f"DB configured. Dialect={engine.url.get_dialect().name}, Driver={engine.url.get_driver_name()}")
except Exception:
    pass
