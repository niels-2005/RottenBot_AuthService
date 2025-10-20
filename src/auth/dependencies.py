from fastapi import Request, status
from fastapi.security import HTTPBearer
from fastapi.security.http import HTTPAuthorizationCredentials
from .utils import decode_token
from fastapi.exceptions import HTTPException
from src.db.redis import token_in_blocklist


class TokenBearer(HTTPBearer):
    """
    Base class for token-based authentication using HTTP Bearer tokens.

    This class extends FastAPI's HTTPBearer to provide JWT token validation,
    including checking for revoked tokens in the blocklist and verifying token type.
    Subclasses must implement the verify_token_data method to specify token requirements.

    Attributes:
        Inherits from HTTPBearer.
    """

    def __init__(self, auto_error=True):
        """
        Initialize the TokenBearer instance.

        Args:
            auto_error (bool): Whether to automatically raise an error if no credentials are provided.
                              Defaults to True.
        """
        super().__init__(auto_error=auto_error)

    async def __call__(self, request: Request) -> HTTPAuthorizationCredentials | None:
        """
        Extract and validate the JWT token from the request.

        Args:
            request (Request): The incoming HTTP request.

        Returns:
            dict: The decoded token data if valid.

        Raises:
            HTTPException: If the token is invalid, revoked, or fails verification.
        """
        creds = await super().__call__(request)

        token = creds.credentials

        token_data = decode_token(token)

        # check if token is in blocklist
        if await token_in_blocklist(token_data["jti"]):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "This token is invalid or has been revoked",
                    "resolution": "Please get new token",
                },
            )

        self.verify_token_data(token_data)

        return token_data

    def verify_token_data(self, token_data):
        """
        Verify the token data according to subclass-specific rules.

        This method should be overridden in subclasses to implement specific
        token type validation (e.g., access vs refresh tokens).

        Args:
            token_data (dict): The decoded JWT token data.

        Raises:
            NotImplementedError: If not overridden in a subclass.
        """
        raise NotImplementedError("Please Override this method in child classes")


class AccessTokenBearer(TokenBearer):
    """
    Bearer token authenticator for access tokens.

    Ensures that the provided token is an access token (not a refresh token).
    """

    def verify_token_data(self, token_data: dict) -> None:
        """
        Verify that the token is an access token.

        Args:
            token_data (dict): The decoded JWT token data.

        Raises:
            HTTPException: If the token is a refresh token.
        """
        if token_data and token_data["refresh"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Please provide an access token",
            )


class RefreshTokenBearer(TokenBearer):
    """
    Bearer token authenticator for refresh tokens.

    Ensures that the provided token is a refresh token (not an access token).
    """

    def verify_token_data(self, token_data: dict) -> None:
        """
        Verify that the token is a refresh token.

        Args:
            token_data (dict): The decoded JWT token data.

        Raises:
            HTTPException: If the token is an access token.
        """
        if token_data and not token_data["refresh"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Please provide a refresh token",
            )
