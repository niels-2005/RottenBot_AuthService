from redis.asyncio import Redis
from src.config import Config
import logging

logger = logging.getLogger(__name__)

# JTI expiry means how long the token identifier will be stored in Redis
JTI_EXPIRY = 3600

# Async Redis Client
token_blocklist = Redis(host=Config.REDIS_HOST, port=Config.REDIS_PORT, db=0)


async def add_jti_to_blocklist(jti: str) -> None:
    try:
        logger.info(f"Adding JTI to blocklist: {jti}")
        await token_blocklist.set(name=jti, value="", ex=JTI_EXPIRY)
        return True
    except Exception as e:
        logger.error(f"Error adding JTI to blocklist: {e}", exc_info=True)
        return None


async def token_in_blocklist(jti: str) -> bool:
    jti_value = await token_blocklist.get(jti)
    return jti_value is not None
