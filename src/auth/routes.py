from fastapi import APIRouter, Depends, HTTPException, status
from sqlmodel.ext.asyncio.session import AsyncSession
from src.db.main import get_session
from .service import UserService
from .schemas import (
    UserCreateDataModel,
    UserLoginModel,
    UserCreateResponseModel,
    UserLoginResponseModel,
)
from .utils import verify_password, create_access_token
from datetime import timedelta

auth_router = APIRouter()
user_service = UserService()

REFRESH_TOKEN_EXPIRY_DAYS = 7


@auth_router.post(
    "/signup",
    response_model=UserCreateResponseModel,
    status_code=status.HTTP_201_CREATED,
)
async def signup_user(
    user_data: UserCreateDataModel,
    session: AsyncSession = Depends(get_session),
):
    """Creates a new user account.

    Args:
        user_data: The user creation data including first_name, last_name, email and password.
        session: The asynchronous database session.

    Returns:
        A response model containing a success message and the created user details.

    Raises:
        HTTPException: If a user with the given email already exists (403 Forbidden).
    """
    if await user_service.user_email_exists(user_data.email, session):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User with email already exists.",
        )

    new_user = await user_service.create_user(user_data, session)

    return UserCreateResponseModel(
        message="User created successfully",
        user=new_user.model_dump(),
    )


@auth_router.post(
    "/login", response_model=UserLoginResponseModel, status_code=status.HTTP_200_OK
)
async def login_user(
    login_data: UserLoginModel, session: AsyncSession = Depends(get_session)
):
    """Authenticates a user and returns access and refresh tokens.

    Args:
        login_data: The login data including email and password.
        session: The asynchronous database session.

    Returns:
        A response model containing a success message, access token, refresh token, and user details.

    Raises:
        HTTPException: If the email or password is invalid (401 Unauthorized).
    """
    user = await user_service.get_user_by_email(login_data.email, session)

    if user is not None:
        password_valid = verify_password(login_data.password, user.password_hash)

        if password_valid:
            # the access tokens lifetime is default 60 minutes
            access_token = create_access_token(
                user_data={
                    "user_uid": str(user.uid),
                }
            )

            # the refresh token lifetime is default 7 days
            refresh_token = create_access_token(
                user_data={
                    "user_uid": str(user.uid),
                },
                expiry=timedelta(days=REFRESH_TOKEN_EXPIRY_DAYS),
                refresh=True,
            )

            return UserLoginResponseModel(
                message="Login successful",
                access_token=access_token,
                refresh_token=refresh_token,
                user=user.model_dump(),
            )

    # if no user found or password is invalid
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid email or password",
    )
