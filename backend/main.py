'''main module for the backend'''

from datetime import timedelta, datetime

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlmodel import SQLModel, select

from database import engine, get_session
from models import User, UserCreate, Token, Unit
from crud import push_user, push_unit, get_user
from auth import (
    create_access_token,
    get_password_hash,
    authenticate_user,
    get_current_active_user,
    )
from sc import ACCESS_TOKEN_EXPIRE_MINUTES

app = FastAPI()


@app.on_event('startup')
async def startup_event():
    """
    creates all the necessary database tables defined in the SQLModel 
    metadata using the provided engine.
    """
    SQLModel.metadata.create_all(engine)




@app.post('/users/new', response_model=User)
async def register(user_data: UserCreate, session=Depends(get_session)):
    '''
    register a new user
    '''
    existing_user = get_user(session, user_data.username) # checks if username is taken
    if existing_user:
        raise HTTPException(status_code=400, detail='Username already taken')

    hashed_password = get_password_hash(user_data.password) # hashing password
    # unpacking a dict with new user info
    user = User(**user_data.dict(), hashed_password=hashed_password)
    return push_user(session, user) # push to db


@app.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    session=Depends(get_session)
):
    """
    Authenticate user and generate an access token.
    This function handles the login process for a user by validating the provided
    username and password. If the authentication is successful, it generates an
    access token with a specified expiration time.
    Args:
        form_data (OAuth2PasswordRequestForm): The form data containing the username and password.
        session: The database session dependency.
    Returns:
        dict: A dictionary containing the access token and token type.
    Raises:
        HTTPException: If the authentication fails, an HTTP 401 Unauthorized exception is raised.
    """
    user = authenticate_user(session, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me/", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    '''returns info about self user'''
    return current_user


# ===============================main functional code block=============================


@app.post("/new", response_model=Unit)
async def create_unit(unit: Unit, session=Depends(get_session)):
    '''creates and pushes a new unit to the database'''
    return push_unit(session, unit)

@app.get("/", response_model=list[Unit])
async def read_units(session=Depends(get_session), offset: int = 0, limit: int = 100):
    """Returns a list of units"""
    data = session.exec(select(Unit).offset(offset).limit(limit)).all()

    for unit in data:
        if hasattr(unit, "last_contact") and unit.last_contact:
            last_contact_date = unit.last_contact

            if isinstance(last_contact_date, str):
                try:
                    last_contact_date = datetime.strptime(last_contact_date, "%Y-%m-%d").date()
                except ValueError:
                    continue 
            
            if (datetime.now().date() - last_contact_date).days < 1:
                continue
        
        if hasattr(unit, "status"):
            unit.status = "not ok"

    return data

@app.get("/units/{unit_id}", response_model=Unit)
async def read_unit(unit_id: int, session=Depends(get_session)):
    '''returns a unit by id'''
    unit = session.get(Unit, unit_id)
    if not unit:
        raise HTTPException(status_code=404, detail="Unit not found")
    return unit


@app.put('/units/{unit_id}', response_model=Unit)
async def update_unit(unit_id: int, new_data: Unit, session=Depends(get_session)):
    '''updates unit data'''
    unit = session.get(Unit, unit_id)
    if not unit:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='unit not found')
    for key, value in new_data.dict().items():
        setattr(unit, key, value)
    return push_unit(session, unit)
