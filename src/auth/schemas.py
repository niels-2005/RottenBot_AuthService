from pydantic import BaseModel, Field
from uuid import UUID
from datetime import datetime


class UserModel(BaseModel):
    """Represents a user in API responses.

    This model is used to return user details in responses from endpoints like signup and login,
    excluding sensitive fields like password hash and verification status.

    Attributes:
        uid: Unique identifier for the user.
        email: User's email address.
        first_name: User's first name.
        last_name: User's last name.
        is_verified: Whether the user's email is verified (excluded from responses).
        password_hash: Hashed password (excluded from responses).
        created_at: Timestamp when the user was created.
        updated_at: Timestamp when the user was last updated.
    """

    uid: UUID
    email: str
    first_name: str
    last_name: str
    is_verified: bool = Field(exclude=True)
    password_hash: str = Field(exclude=True)
    created_at: datetime
    updated_at: datetime


class UserCreateDataModel(BaseModel):
    """Represents data required to create a new user.

    This model is used as input for the signup endpoint to collect user registration details.

    Attributes:
        first_name: User's first name.
        last_name: User's last name.
        email: User's email address.
        password: User's plain-text password.
    """

    first_name: str
    last_name: str
    email: str
    password: str


class UserCreateResponseModel(BaseModel):
    """Represents the response for user creation.

    This model is used as the response for the signup endpoint, providing confirmation and user details.

    Attributes:
        message: Success message for user creation.
        user: Details of the created user.
    """

    message: str
    user: UserModel


class UserLoginModel(BaseModel):
    """Represents data required for user login.

    This model is used as input for the login endpoint to authenticate a user.

    Attributes:
        email: User's email address.
        password: User's plain-text password.
    """

    email: str
    password: str


class UserLoginResponseModel(BaseModel):
    """Represents the response for user login.

    This model is used as the response for the login endpoint, providing tokens and user details.

    Attributes:
        message: Success message for login.
        access_token: JWT access token for authenticated requests.
        refresh_token: JWT refresh token to obtain new access tokens.
        user: Details of the logged-in user.
    """

    message: str
    access_token: str
    refresh_token: str
    user: UserModel
