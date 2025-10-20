from redis.asyncio import Redis
from src.config import Config
import logging

logger = logging.getLogger(__name__)

# JTI expiry means how long the token identifier will be stored in Redis (3600 seconds = 1 hour)
JTI_EXPIRY = 3600

# Async Redis Client
token_blocklist = Redis(
    host=Config.REDIS_HOST,
    port=Config.REDIS_PORT,
    password=Config.REDIS_PASSWORD,
    db=0,
)


async def add_jti_to_blocklist(jti: str) -> bool | None:
    """Add a JWT ID (JTI) to the blocklist. This is needed to invalidate tokens on logout.

    Args:
        jti (str): The JWT ID to add to the blocklist.

    Returns:
        True | None: True if the JTI was added successfully, None otherwise.
    """
    try:
        logger.info(f"Adding JTI to blocklist: {jti}")
        await token_blocklist.set(name=jti, value="", ex=JTI_EXPIRY)
        return True
    except Exception as e:
        logger.error(f"Error adding JTI to blocklist: {e}", exc_info=True)
        return None


async def token_in_blocklist(jti: str) -> bool | None:
    """Check if a JWT ID (JTI) is in the blocklist.

    Args:
        jti (str): The JWT ID to check.

    Returns:
        bool | None: True if the JTI is in the blocklist, False if not, None if an error occurred.
    """
    try:
        logger.info(f"Checking if JTI is in blocklist: {jti}")
        jti_value = await token_blocklist.get(jti)
        return jti_value is not None
    except Exception as e:
        logger.error(f"Error checking JTI in blocklist: {e}", exc_info=True)
        return None
