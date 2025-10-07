# db.py
import os
from sqlalchemy import create_engine, text
from urllib.parse import urlparse

raw_url = os.environ.get("DATABASE_URL")

if not raw_url:
    # Fallback so the app still runs locally without Render
    raw_url = "sqlite:///database.db"

# Normalize scheme (Render sometimes exposes postgres://)
if raw_url.startswith("postgres://"):
    raw_url = raw_url.replace("postgres://", "postgresql+psycopg2://", 1)

# For SQLite we want a file; for Postgres we want a proper DSN
engine = create_engine(
    raw_url,
    pool_pre_ping=True,
    future=True,          # SQLAlchemy 2.x style
)
