import os
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy import URL
from sqlalchemy.ext.asyncio import (
    async_sessionmaker,
    create_async_engine,
)

load_dotenv(Path(__file__).with_name(".env"))

database_url = URL.create(
    drivername="postgresql+asyncpg",
    username="visitor_app",
    password=os.environ["DB_PASSWORD"],
    host="127.0.0.1",
    port=5432,
    database="visitor_registration",
)

engine = create_async_engine(database_url)
Session = async_sessionmaker(engine, expire_on_commit=False)