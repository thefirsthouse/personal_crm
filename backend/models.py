from sqlmodel import Field, SQLModel
from datetime import datetime

class Unit(SQLModel, table=True):
    id: int = Field(default=None, primary_key=True)
    name: str = Field(index=True)
    last_contact: datetime = Field(default=None, index=True)
    status: str = Field(index=True)
    info: str | None = Field()

class UserBase(SQLModel):
    username: str = Field(index=True, unique=True)
    email: str = Field(unique=True)
    full_name: str | None = None
    disabled: bool | None = None

class UserCreate(UserBase):
    password: str

class User(UserBase, table=True):
    id: int = Field(default=None, primary_key=True)
    hashed_password: str

class Token(SQLModel):
    access_token: str
    token_type: str

class TokenData(SQLModel):
    username: str | None = None