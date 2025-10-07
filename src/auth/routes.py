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
from .utils import verify_password, create_access_token
from datetime import timedelta, datetime
from .dependencies import RefreshTokenBearer, AccessTokenBearer
from src.db.redis import add_jti_to_blocklist
import logging
from .setup_observability import setup_observability
import time

tracer, meter = setup_observability("auth_service")
logger = logging.getLogger(__name__)


auth_router = APIRouter()
user_service = UserService()

REFRESH_TOKEN_EXPIRY_DAYS = 7


auth_api_counter = meter.create_counter(
    name="auth_api_requests_total",
    description="Total number of auth API requests",
    unit="1",
)

auth_api_duration = meter.create_histogram(
    name="auth_api_duration_milliseconds",
    description="Auth API request duration",
    unit="ms",
)


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
    try:
        with tracer.start_as_current_span("signup_endpoint") as signup_entry_span:
            logger.info("Signup endpoint called")
            start_time = time.time()
            auth_api_counter.add(
                1,
                {
                    "endpoint": "/signup",
                    "method": "POST",
                    "service_name": "auth_service",
                },
            )

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
    except Exception as e:
        logger.error(f"Error in signup_user: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Oops. Something went wrong. Please try again later.",
        )
    finally:
        duration_ms = (time.time() - start_time) * 1000
        auth_api_duration.record(
            duration_ms,
            {
                "endpoint": "/signup",
                "method": "POST",
                "service_name": "auth_service",
            },
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
    try:
        with tracer.start_as_current_span("signup_endpoint") as signup_entry_span:
            logger.info("Login endpoint called")
            start_time = time.time()
            auth_api_counter.add(
                1,
                {
                    "endpoint": "/login",
                    "method": "POST",
                    "service_name": "auth_service",
                },
            )
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

                    if access_token or refresh_token is None:
                        # error already logged in create_access_token
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

    except Exception as e:
        logger.error(f"Error in login_user: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Oops. Something went wrong. Please try again later.",
        )
    finally:
        duration_ms = (time.time() - start_time) * 1000
        auth_api_duration.record(
            duration_ms,
            {
                "endpoint": "/login",
                "method": "POST",
                "service_name": "auth_service",
            },
        )


@auth_router.get(
    "/logout", response_model=LogoutResponseModel, status_code=status.HTTP_200_OK
)
async def revoke_token(token_details: dict = Depends(AccessTokenBearer())):
    """Revokes the access token by adding its JTI to the blocklist.

    Args:
        token_details: The token details obtained from the access token bearer.

    Returns:
        A response model containing a success message for logout.
    """
    try:
        with tracer.start_as_current_span("logout_endpoint") as logout_entry_span:
            logger.info("Logout endpoint called")
            start_time = time.time()
            auth_api_counter.add(
                1,
                {
                    "endpoint": "/logout",
                    "method": "POST",
                    "service_name": "auth_service",
                },
            )

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

    except Exception as e:
        logger.error(f"Error in revoke_token (Logout Endpoint): {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Oops. Something went wrong. Please try again later.",
        )
    finally:
        duration_ms = (time.time() - start_time) * 1000
        auth_api_duration.record(
            duration_ms,
            {
                "endpoint": "/logout",
                "method": "POST",
                "service_name": "auth_service",
            },
        )


@auth_router.get(
    "/refresh_token",
    response_model=RefreshTokenResponseModel,
    status_code=status.HTTP_200_OK,
)
async def get_new_access_token(token_details: dict = Depends(RefreshTokenBearer())):
    """Generates a new access token using a valid refresh token.

    Args:
        token_details: The token details obtained from the refresh token bearer.

    Returns:
        A response model containing the new access token.

    Raises:
        HTTPException: If the refresh token is invalid or expired (400 Bad Request).
    """
    try:
        with tracer.start_as_current_span(
            "refresh_token_endpoint"
        ) as refresh_entry_span:
            logger.info("Refresh Token endpoint called")
            start_time = time.time()
            auth_api_counter.add(
                1,
                {
                    "endpoint": "/refresh_token",
                    "method": "GET",
                    "service_name": "auth_service",
                },
            )

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

    except Exception as e:
        logger.error(f"Error in get_new_access_token: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Oops. Something went wrong. Please try again later.",
        )

    finally:
        duration_ms = (time.time() - start_time) * 1000
        auth_api_duration.record(
            duration_ms,
            {
                "endpoint": "/refresh_token",
                "method": "GET",
                "service_name": "auth_service",
            },
        )
