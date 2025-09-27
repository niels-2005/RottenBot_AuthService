import uuid
from datetime import datetime
import sqlalchemy.dialects.postgresql as pg
from sqlmodel import Column, Field, SQLModel


class User(SQLModel, table=True):
    """Represents a user account in the database.

    This model defines the structure of the 'user_accounts' table, including
    user identification, authentication details, and metadata.

    Attributes:
        uid: Unique identifier for the user (UUID, primary key).
        role: User's role in the system (default: 'user').
        first_name: User's first name.
        last_name: User's last name.
        is_verified: Whether the user's email is verified (default: False).
        email: User's email address (unique).
        password_hash: Hashed password for authentication.
        created_at: Timestamp when the user was created.
        updated_at: Timestamp when the user was last updated.
    """

    __tablename__ = "user_accounts"

    uid: uuid.UUID = Field(
        sa_column=Column(
            pg.UUID,
            primary_key=True,
            unique=True,
            nullable=False,
            default=uuid.uuid4,
        )
    )

    role: str = Field(
        sa_column=Column(pg.VARCHAR, nullable=False, server_default="user")
    )

    first_name: str = Field(sa_column=Column(pg.VARCHAR, nullable=False))
    last_name: str = Field(sa_column=Column(pg.VARCHAR, nullable=False))
    is_verified: bool = Field(
        sa_column=Column(pg.BOOLEAN, nullable=False, default=False)
    )
    email: str = Field(sa_column=Column(pg.VARCHAR, unique=True, nullable=False))
    password_hash: str = Field(sa_column=Column(pg.VARCHAR, nullable=False))
    created_at: datetime = Field(sa_column=Column(pg.TIMESTAMP, default=datetime.now))
    updated_at: datetime = Field(sa_column=Column(pg.TIMESTAMP, default=datetime.now))

    def __repr__(self) -> str:
        return f"<User {self.email}>"
