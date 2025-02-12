from pydantic import BaseModel

class TokenSchema(BaseModel):
    '''
    {
        "access_token": "access-token-here",
        "token_type": "bearer"
    }
    '''
    access_token: str
    token_type: str

class UserSchema(BaseModel):
    username: str
    email: str
    full_name: str | None