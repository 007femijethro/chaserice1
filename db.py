# db.py
import os
from sqlalchemy import create_engine

raw_url = os.environ.get("DATABASE_URL", "postgresql://localhost/postgres")

# Normalize scheme from Heroku/Render style
if raw_url.startswith("postgres://"):
    raw_url = raw_url.replace("postgres://", "postgresql://", 1)

# Force psycopg 3 driver instead of psycopg2
if raw_url.startswith("postgresql://") and "+psycopg" not in raw_url:
    raw_url = raw_url.replace("postgresql://", "postgresql+psycopg://", 1)

engine = create_engine(raw_url, pool_pre_ping=True, future=True)
