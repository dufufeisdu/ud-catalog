from flask import Flask, render_template, request, redirect, jsonify, url_for, flash
app = Flask(__name__)

from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, User, Item
from flask.ext.httpauth import HTTPBasicAuth

auth = HTTPBasicAuth()

# Connect to Database and create database session
engine = create_engine('sqlite:///catelog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


def isLogin():
    return False


@auth.verify_password
def verify_password(username, password):
    user = session.query(User).filter_by(username=username).first()
    if not user:
        print "User not found"
        return False
    elif not user.verify_password(password):
        print "Unable to verfy password"
        return False
    else:
        g.user = user
        return True


@app.route('/')
def showCategory():
  # 1th user is the public
    if isLogin() is False:
        # user_id 1 is the reserved public resource
        publicCategory = session.query(
            Category).filter(Category.user_id == 1).all()
        publicItem = session.query(Item.name).filter(
            Item.user_id == 1).all()
        return render_template('public.html', category=publicCategory, item=publicItem)

    categories = session.query(Category.name, User.id).fliter(Category.name == g.user.username).
    filter(Category.user_id == User.id).all()
    user_id = categories.id
    items = session.query(Item.name).filter(Item.user_id == user_id).all()
    return render_template('logedInCata.html', category=categories, item=items)

    # for a in publicCategory:
    #     print(a)


@app.route('/catalog/<name>/Items')
def showItems(name):
    session.query()


@app.route('/catalog/<name>/<item>')
def showSubItems:


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
