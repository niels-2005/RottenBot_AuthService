import uuid
from datetime import datetime, timedelta

import jwt
from passlib.context import CryptContext
from src.config import Config
from src.auth.setup_observability import get_meter
import logging

meter = get_meter(__name__)
logger = logging.getLogger(__name__)

passwd_context = CryptContext(schemes=["bcrypt"])

# a meter to track auth API requests
auth_api_counter = meter.create_counter(
    name="auth_api_requests_total",
    description="Total number of auth API requests",
    unit="1",
)

# a histogram to track auth API request durations
auth_api_duration = meter.create_histogram(
    name="auth_api_duration_milliseconds",
    description="Auth API request duration",
    unit="ms",
)


def increase_auth_api_counter(endpoint_config: dict[str, str]) -> None:
    """Increases the auth API counter for a specific endpoint.

    Args:
        endpoint_config (dict[str, str]): Configuration for the endpoint.
    """
    try:
        auth_api_counter.add(1, **endpoint_config)
    except Exception as e:
        logger.error(
            f"Error increasing auth API counter for endpoint {endpoint_config['endpoint']}: {e}",
            exc_info=True,
        )


def record_auth_api_duration(
    duration_ms: float, endpoint_config: dict[str, str]
) -> None:
    """Records the duration of an auth API request for a specific endpoint.

    Args:
        duration_ms (float): The duration of the API request in milliseconds.
        endpoint_config (dict[str, str]): Configuration for the endpoint.
    """
    try:
        auth_api_duration.record(duration_ms, **endpoint_config)
    except Exception as e:
        logger.error(
            f"Error recording auth API duration for endpoint {endpoint_config['endpoint']}: {e}",
            exc_info=True,
        )


def generate_password_hash(password: str) -> str:
    """Generates a hashed version of the provided password using bcrypt.

    Args:
        password: The plain-text password to hash.

    Returns:
        The hashed password as a string.
    """
    try:
        hash = passwd_context.hash(password)
        return hash
    except Exception as e:
        logger.error(f"Error hashing password: {e}", exc_info=True)


def verify_password(password: str, hash: str) -> bool:
    """Verifies a plain-text password against its hashed version.

    Args:
        password: The plain-text password to verify.
        hash: The hashed password to compare against.

    Returns:
        True if the password matches the hash, False otherwise.
    """
    try:
        return passwd_context.verify(password, hash)
    except Exception as e:
        logger.error(f"Error verifying password: {e}", exc_info=True)


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
    try:
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
    except Exception as e:
        logger.error(f"Error creating access token: {e}", exc_info=True)
        return None


def decode_token(token: str) -> dict:
    """Decodes a JWT token and returns its payload.

    Args:
        token: The JWT token to decode.

    Returns:
        A dictionary containing the decoded token payload.
    """
    try:
        return jwt.decode(
            jwt=token, algorithms=[Config.JWT_ALGORITHM], key=Config.JWT_SECRET
        )
    except Exception as e:
        logger.error(f"Error decoding token: {e}", exc_info=True)
