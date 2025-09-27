from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlmodel import SQLModel
from sqlmodel.ext.asyncio.session import AsyncSession
from src.config import Config

async_engine = create_async_engine(
    url=Config.DATABASE_URL,
    echo=True,
)


async def init_db() -> None:
    async with async_engine.begin() as conn:
        # erstellt eine neue Book Datenbank durch Import oben
        await conn.run_sync(SQLModel.metadata.create_all)


# get current session
async def get_session():
    Session = sessionmaker(
        bind=async_engine, class_=AsyncSession, expire_on_commit=False
    )
    async with Session() as session:
        yield session
