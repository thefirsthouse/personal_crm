'''module for user authentication'''

from datetime import datetime, timedelta, timezone
from jwt import encode, decode
from jwt.exceptions import InvalidTokenError
from fastapi import HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext
from sqlmodel import Session

from database import get_session
from models import User
from crud import get_user
from sc import SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto") # setting up the hash context

# setting up OAuth2 for authorization via Bearer Token (token gets from /token)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl='token')

def verify_password(plain_password, hashed_password):
    """
    checks the match of the password and its hash
    """
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    """hashing plain password"""
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    """
    Creates a JSON Web Token (JWT) for the given data with an optional expiration time.
    Args:
        data (dict): The data to be encoded in the token.
        expires_delta (timedelta | None, optional): 
            The time duration after which the token will expire. 
            If not provided, the token will expire after a default duration 
            specified by ACCESS_TOKEN_EXPIRE_MINUTES.
    Returns:
        str: The encoded JWT as a string.
    """
    to_encode = data.copy()
    expire = (datetime.now(timezone.utc)
              + (expires_delta or timedelta(ACCESS_TOKEN_EXPIRE_MINUTES)))
    to_encode.update({'exp': expire})
    return encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def authenticate_user(session: Session, username: str, password: str) -> User | None:
    """Checks entered username and password"""
    user = get_user(session, username)
    if user and verify_password(password, user.hashed_password):
        return user
    return None


async def get_current_user(token: str = Depends(oauth2_scheme), session=Depends(get_session)):
    """
    Retrieve the current user based on the provided JWT token.
    Args:
        token (str): The JWT token provided by the user.
        session: The database session dependency.
    Returns:
        User: The authenticated user object.
    Raises:
        HTTPException: If the token is invalid or the user cannot be authenticated.
    """
    credentials_exceprion = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail='Invalid authenticaton credentials',
        headers={'WWW-Authenticate': 'Bearer'},
    )
    try:
        payload = decode(token, SECRET_KEY, algorithms=ALGORITHM)
        username: str | None = payload.get('sub')
        if not username:
            raise credentials_exceprion
        user = get_user(session, username)
        if not user:
            raise credentials_exceprion
        return user
    except InvalidTokenError as exc:
        raise credentials_exceprion from exc


async def get_current_active_user(current_user: User = Depends(get_current_user)):
    '''checks user for active/disabled'''
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user
