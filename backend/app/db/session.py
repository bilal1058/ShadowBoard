import os
import aiosqlite
from pathlib import Path

DB_PATH = Path(__file__).parent.parent.parent / "shadowboard.db"
SCHEMA_PATH = Path(__file__).parent / "schema.sql"

async def get_db():
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        await db.execute("PRAGMA journal_mode=WAL;")
        await db.execute("PRAGMA foreign_keys=ON;")
        yield db

async def init_db():
    """Initialize database schema. For development: clean reset.
    For production: implement proper migrations.
    """
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("PRAGMA journal_mode=WAL;")
        await db.execute("PRAGMA foreign_keys=ON;")
        with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
            schema_sql = f.read()
        await db.executescript(schema_sql)
        await db.commit()
