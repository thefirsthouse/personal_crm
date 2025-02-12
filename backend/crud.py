'''module for database operations'''

from sqlmodel import select, Session
from models import User, Unit

def get_user(session: Session, username: str) -> User | None:
    '''get user by username'''
    return session.exec(select(User).where(User.username == username)).first()


def push_user(session: Session, user: User):
    '''add user to database'''
    session.add(user)
    session.commit()
    session.refresh(user)
    return user

def push_unit(session: Session, unit: Unit):
    '''add unit to database'''
    session.add(unit)
    session.commit()
    session.refresh(unit)
    return unit
