# usr/bin/python2
from init_database import Base, User, Category, Item
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

engine = create_engine('sqlite:///catelog.db')

Base.metadata.bind = engine
DBsession = sessionmaker(bind=engine)
session = DBsession()
publicUser = User(username='public', password_hash=None)
session.add(publicUser)
session.commit()
publicCata = Category(name='Soccer', user=publicUser)
session.add(publicCata)
session.commit()
publicItem1 = Item(title='Player', description='''There are 22 players in the stadium''',
                   user=publicUser, category=publicCata)
publicItem2 = Item(title='Judge', description='''There are 4 judges in the game one referee, two associate referee and one fourth official''',
                   user=publicUser, category=publicCata)
session.add(publicItem1)
session.add(publicItem2)
session.commit()
publicCata = Category(name='Basketball', user=publicUser)
session.add(publicCata)
session.commit()
publicItem1 = Item(title='Player', description='''There are 10 players in the stadium''',
                   user=publicUser, category=publicCata)
publicItem2 = Item(title='Judge', description='''There are 2 or 3 officials in the game one crew chief, one or two referee''',
                   user=publicUser, category=publicCata)
session.add(publicItem1)
session.add(publicItem2)
session.commit()
