from fastapi import APIRouter, Depends, HTTPException, status
from sqlmodel.ext.asyncio.session import AsyncSession
from src.db.main import get_session
from .service import UserService
from .schemas import (
    UserCreateDataModel,
    UserLoginModel,
    UserCreateResponseModel,
    UserLoginResponseModel,
    RefreshTokenResponseModel,
    LogoutResponseModel,
)
from .utils import (
    verify_password,
    create_access_token,
    increase_auth_api_counter,
    record_auth_api_duration,
)
from datetime import timedelta, datetime
from .dependencies import RefreshTokenBearer, AccessTokenBearer
from src.db.redis import add_jti_to_blocklist
import logging
from .setup_observability import get_tracer
import time

tracer = get_tracer(__name__)
logger = logging.getLogger(__name__)


auth_router = APIRouter()
user_service = UserService()

# the refresh tokens expire in 7 days, then the user needs to login again
REFRESH_TOKEN_EXPIRY_DAYS = 7


@auth_router.post(
    "/signup",
    response_model=UserCreateResponseModel,
    status_code=status.HTTP_201_CREATED,
)
async def signup_user(
    user_data: UserCreateDataModel,
    session: AsyncSession = Depends(get_session),
    endpoint_config: dict[str, str] = {
        "endpoint": "/signup",
        "method": "POST",
        "service_name": "auth_service",
    },
):
    """
    Creates a new user account with observability tracking.

    This endpoint performs the following operations:
    1. Checks if a user with the provided email already exists
    2. Creates a new user account if the email is available
    3. Records API metrics and tracing information

    Args:
        user_data (UserCreateDataModel): The user creation data including first_name, last_name, email and password.
        session (AsyncSession): The asynchronous database session for database operations.
        endpoint_config (dict[str, str]): Configuration for observability metrics and tracing.

    Returns:
        UserCreateResponseModel: A response model containing a success message and the created user details.

    Raises:
        HTTPException: If a user with the given email already exists (403 Forbidden) or if internal errors occur (500 Internal Server Error).
    """
    try:
        with tracer.start_as_current_span("signup_endpoint") as signup_entry_span:
            logger.info("Signup endpoint called")
            start_time = time.time()
            increase_auth_api_counter(endpoint_config)

            with tracer.start_as_current_span("check_user_exists") as check_user_span:
                logger.info("Checking if user with email already exists.")

                user_exists = await user_service.user_email_exists(
                    user_data.email, session
                )

                if user_exists:
                    logger.info("User with email already exists.")
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="User with email already exists.",
                    )

                if user_exists is None:
                    # error already logged in user_email_exists
                    raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        detail="Oops. Something went wrong. Please try again later.",
                    )

            with tracer.start_as_current_span("create_user") as create_user_span:
                logger.info("Creating new user.")
                new_user = await user_service.create_user(user_data, session)

                if new_user is None:
                    # error already logged in create_user
                    raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        detail="Oops. Something went wrong. Please try again later.",
                    )

            logger.info("User created successfully.")
            return UserCreateResponseModel(
                message="User created successfully",
                user=new_user.model_dump(),
            )
    finally:
        # record the duration from the endpoint for observability
        duration_ms = (time.time() - start_time) * 1000
        record_auth_api_duration(duration_ms, endpoint_config)


@auth_router.post(
    "/login", response_model=UserLoginResponseModel, status_code=status.HTTP_200_OK
)
async def login_user(
    login_data: UserLoginModel,
    session: AsyncSession = Depends(get_session),
    endpoint_config: dict[str, str] = {
        "endpoint": "/login",
        "method": "POST",
        "service_name": "auth_service",
    },
):
    """
    Authenticates a user and returns access and refresh tokens with observability tracking.

    This endpoint performs the following operations:
    1. Retrieves the user by email from the database
    2. Verifies the provided password against the stored hash
    3. Generates access and refresh tokens if authentication succeeds
    4. Records API metrics and tracing information

    Args:
        login_data (UserLoginModel): The login data including email and password.
        session (AsyncSession): The asynchronous database session for database operations.
        endpoint_config (dict[str, str]): Configuration for observability metrics and tracing.

    Returns:
        UserLoginResponseModel: A response model containing a success message, access token, refresh token, and user details.

    Raises:
        HTTPException: If the email or password is invalid (401 Unauthorized) or if internal errors occur (500 Internal Server Error).
    """
    try:
        with tracer.start_as_current_span("signup_endpoint") as signup_entry_span:
            logger.info("Login endpoint called")
            start_time = time.time()
            increase_auth_api_counter(endpoint_config)

            with tracer.start_as_current_span(
                "get_user_by_email"
            ) as get_user_by_email_span:
                logger.info("Getting user by email.")
                user = await user_service.get_user_by_email(login_data.email, session)

            if user is not None:
                with tracer.start_as_current_span(
                    "verify_user_password"
                ) as verify_user_password_span:
                    logger.info(f"Verifying user password for user: {user.uid}.")
                    password_valid = verify_password(
                        login_data.password, user.password_hash
                    )

                if password_valid:
                    with tracer.start_as_current_span(
                        "create_access_and_refresh_token"
                    ) as create_tokens_span:
                        logger.info(
                            f"Creating access and refresh tokens for user: {user.uid}."
                        )
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

                    if access_token is None or refresh_token is None:
                        raise HTTPException(
                            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail="Oops. Something went wrong. Please try again later.",
                        )

                    logger.info("User logged in successfully.")
                    return UserLoginResponseModel(
                        message="Login successful",
                        access_token=access_token,
                        refresh_token=refresh_token,
                        user=user.model_dump(),
                    )

            logger.info("Invalid email or password attempt.")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password",
            )
    finally:
        duration_ms = (time.time() - start_time) * 1000
        record_auth_api_duration(duration_ms, endpoint_config)


@auth_router.get(
    "/logout", response_model=LogoutResponseModel, status_code=status.HTTP_200_OK
)
async def revoke_token(
    token_details: dict = Depends(AccessTokenBearer()),
    endpoint_config: dict[str, str] = {
        "endpoint": "/logout",
        "method": "POST",
        "service_name": "auth_service",
    },
):
    """
    Revokes the access token by adding its JTI to the blocklist with observability tracking.

    This endpoint performs the following operations:
    1. Validates the provided access token
    2. Adds the token's JTI (JWT ID) to the Redis blocklist
    3. Records API metrics and tracing information

    Args:
        token_details (dict): The token details obtained from the access token bearer, containing user info and JTI.
        endpoint_config (dict[str, str]): Configuration for observability metrics and tracing.

    Returns:
        LogoutResponseModel: A response model containing a success message for logout.

    Raises:
        HTTPException: If the token is invalid/revoked (from AccessTokenBearer) or if internal errors occur (500 Internal Server Error).
    """
    try:
        with tracer.start_as_current_span("logout_endpoint") as logout_entry_span:
            logger.info("Logout endpoint called")
            start_time = time.time()
            increase_auth_api_counter(endpoint_config)

            logger.info("Adding JTI to blocklist.")
            jti_to_blocklist_succeeded = await add_jti_to_blocklist(
                token_details["jti"]
            )

            if jti_to_blocklist_succeeded:
                logger.info("User logged out successfully.")
                return LogoutResponseModel(message="Logged Out Successfully")

            if jti_to_blocklist_succeeded is None:
                # error already logged in add_jti_to_blocklist
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Oops. Something went wrong. Please try again later.",
                )
    finally:
        duration_ms = (time.time() - start_time) * 1000
        record_auth_api_duration(duration_ms, endpoint_config)


@auth_router.get(
    "/refresh_token",
    response_model=RefreshTokenResponseModel,
    status_code=status.HTTP_200_OK,
)
async def get_new_access_token(
    token_details: dict = Depends(RefreshTokenBearer()),
    endpoint_config: dict[str, str] = {
        "endpoint": "/refresh_token",
        "method": "GET",
        "service_name": "auth_service",
    },
):
    """
    Generates a new access token using a valid refresh token with observability tracking.

    This endpoint performs the following operations:
    1. Validates the provided refresh token
    2. Checks if the refresh token hasn't expired
    3. Generates a new access token with the same user data
    4. Records API metrics and tracing information

    Args:
        token_details (dict): The token details obtained from the refresh token bearer, containing user info, exp timestamp, etc.
        endpoint_config (dict[str, str]): Configuration for observability metrics and tracing.

    Returns:
        RefreshTokenResponseModel: A response model containing the new access token.

    Raises:
        HTTPException: If the refresh token is invalid, expired, or revoked (400 Bad Request) or if token validation fails (from RefreshTokenBearer).
    """
    try:
        with tracer.start_as_current_span(
            "refresh_token_endpoint"
        ) as refresh_entry_span:
            logger.info("Refresh Token endpoint called")
            start_time = time.time()
            increase_auth_api_counter(endpoint_config)

        expiry_timestamp = token_details["exp"]

        # Check if the refresh token is still valid
        if datetime.fromtimestamp(expiry_timestamp) > datetime.now():
            logger.info("Generating new access token from refresh token.")
            new_access_token = create_access_token(user_data=token_details["user"])
            return RefreshTokenResponseModel(access_token=new_access_token)
        else:
            logger.info("Expired or invalid refresh token used.")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid Or expired token. Please login again",
            )
    finally:
        duration_ms = (time.time() - start_time) * 1000
        record_auth_api_duration(duration_ms, endpoint_config)
