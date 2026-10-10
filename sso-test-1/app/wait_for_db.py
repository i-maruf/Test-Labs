import os
import time

from sqlalchemy import text

from models import make_engine, Base

url = os.environ.get("DATABASE_URL", "postgresql://sso:sso@db:5432/ssodb")
deadline = time.time() + int(os.environ.get("DB_WAIT_SECONDS", "60"))
engine = make_engine(url)

while True:
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        break
    except Exception as exc:
        if time.time() >= deadline:
            raise SystemExit(f"Database not ready: {exc}") from exc
        time.sleep(1)

Base.metadata.create_all(engine)
