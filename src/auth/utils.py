import uuid
from datetime import datetime, timedelta

import jwt
from passlib.context import CryptContext
from src.config import Config

passwd_context = CryptContext(schemes=["bcrypt"])


def generate_password_hash(password: str) -> str:
    """Generates a hashed version of the provided password using bcrypt.

    Args:
        password: The plain-text password to hash.

    Returns:
        The hashed password as a string.
    """
    hash = passwd_context.hash(password)
    return hash


def verify_password(password: str, hash: str) -> bool:
    """Verifies a plain-text password against its hashed version.

    Args:
        password: The plain-text password to verify.
        hash: The hashed password to compare against.

    Returns:
        True if the password matches the hash, False otherwise.
    """
    return passwd_context.verify(password, hash)


def create_access_token(
    user_data: dict, expiry: timedelta = None, refresh: bool = False
) -> str:
    """Creates a JWT access token with user data and optional expiry.

    Args:
        user_data: A dictionary containing user information to include in the token payload.
        expiry: Optional timedelta for token expiration. Defaults to 60 minutes if None.
        refresh: Boolean indicating if this is a refresh token. Defaults to False.

    Returns:
        The encoded JWT token as a string.
    """
    payload = {
        "user": user_data,
        "exp": datetime.now()
        + (expiry if expiry is not None else timedelta(minutes=60)),
        "jti": str(uuid.uuid4()),
        "refresh": refresh,
    }

    token = jwt.encode(
        payload=payload, key=Config.JWT_SECRET, algorithm=Config.JWT_ALGORITHM
    )
    return token


def decode_token(token: str) -> dict:
    """Decodes a JWT token and returns its payload.

    Args:
        token: The JWT token to decode.

    Returns:
        A dictionary containing the decoded token payload.
    """
    token_data = jwt.decode(
        jwt=token, algorithms=[Config.JWT_ALGORITHM], key=Config.JWT_SECRET
    )
    return token_data
