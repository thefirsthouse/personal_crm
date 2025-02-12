'''module to create a session to interact with the database'''

from sqlmodel import Session, create_engine

SQLITE_FILE_NAME = 'database.db'
sqlite_url = f'sqlite:///{SQLITE_FILE_NAME}'

connect_args = {"check_same_thread": False}
engine = create_engine(sqlite_url, connect_args=connect_args)


def get_session():
    '''function to create a session to interact with the database'''
    with Session(engine) as session:
        yield session
