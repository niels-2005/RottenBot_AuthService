from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlmodel import SQLModel
from sqlmodel.ext.asyncio.session import AsyncSession
from src.config import Config
from src.auth.models import User


# create the async engine for the database connection
async_engine = create_async_engine(
    url=Config.DATABASE_URL,
    echo=True,
)

async def init_db() -> None:
    """Initialize the database.
    """
    async with async_engine.begin() as conn:
        # creates the User table because the import above
        await conn.run_sync(SQLModel.metadata.create_all)


async def get_session():
    """Get the database session.

    Yields:
        AsyncSession: The database session.
    """
    Session = sessionmaker(
        bind=async_engine, class_=AsyncSession, expire_on_commit=False
    )
    async with Session() as session:
        yield session
