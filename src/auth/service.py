from sqlmodel.ext.asyncio.session import AsyncSession
from sqlmodel import select
from .models import User
from .utils import generate_password_hash
from .schemas import UserCreateDataModel
from .setup_observability import get_tracer
import logging

tracer = get_tracer(__name__)
logger = logging.getLogger(__name__)


class UserService:
    async def get_user_by_email(self, email: str, session: AsyncSession) -> User | None:
        """Retrieves a user by their email address.

        Args:
            email: The email address of the user to retrieve.
            session: The asynchronous database session.

        Returns:
            The User object if found, otherwise None.
        """
        try:
            with tracer.start_as_current_span(
                "get_user_by_email_from_db"
            ) as get_user_by_email_from_db_span:
                logger.info("Getting user by email from database.")
                result = await session.exec(select(User).where(User.email == email))
                return result.first()

        except Exception as e:
            logger.error(f"Error retrieving user by email: {e}", exc_info=True)
            return None

    async def user_email_exists(self, email: str, session: AsyncSession) -> bool:
        """Checks if a user with the given email address exists.

        Args:
            email: The email address to check.
            session: The asynchronous database session.

        Returns:
            True if a user with the email exists, False otherwise.
        """
        try:
            with tracer.start_as_current_span(
                "check_user_by_email"
            ) as check_user_by_email_span:
                logger.info("Getting user by email.")
                user = await self.get_user_by_email(email, session)
                return True if user is not None else False

        except Exception as e:
            logger.error(f"Error checking if user email exists: {e}", exc_info=True)
            return None

    async def create_user(
        self, user_data: UserCreateDataModel, session: AsyncSession
    ) -> User:
        """Creates a new user in the database.

        Args:
            user_data: The user creation data model containing user details.
            session: The asynchronous database session.

        Returns:
            The newly created User object.
        """
        try:
            user_data_dict = user_data.model_dump()
            new_user = User(**user_data_dict)
            with tracer.start_as_current_span("hash_password") as hash_password_span:
                logger.info("Hashing user password.")
                new_user.password_hash = generate_password_hash(
                    user_data_dict["password"]
                )

                if new_user.password_hash is None:
                    # error already logged in generate_password_hash
                    return None

            with tracer.start_as_current_span("add_user_to_db") as add_user_db_span:
                logger.info("Adding new user to database.")
                session.add(new_user)
                await session.commit()

            return new_user

        except Exception as e:
            logger.error(f"Error creating user: {e}", exc_info=True)
            return None
