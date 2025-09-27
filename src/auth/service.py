from sqlmodel.ext.asyncio.session import AsyncSession
from sqlmodel import select
from .models import User
from .utils import generate_password_hash
from .schemas import UserCreateDataModel


class UserService:
    async def get_user_by_email(self, email: str, session: AsyncSession) -> User | None:
        """Retrieves a user by their email address.

        Args:
            email: The email address of the user to retrieve.
            session: The asynchronous database session.

        Returns:
            The User object if found, otherwise None.
        """
        result = await session.exec(select(User).where(User.email == email))
        return result.first()

    async def user_email_exists(self, email: str, session: AsyncSession) -> bool:
        """Checks if a user with the given email address exists.

        Args:
            email: The email address to check.
            session: The asynchronous database session.

        Returns:
            True if a user with the email exists, False otherwise.
        """
        user = await self.get_user_by_email(email, session)
        return True if user is not None else False

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
        user_data_dict = user_data.model_dump()
        new_user = User(**user_data_dict)
        new_user.password_hash = generate_password_hash(user_data_dict["password"])
        session.add(new_user)
        await session.commit()
        return new_user
