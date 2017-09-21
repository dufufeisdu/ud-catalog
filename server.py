from flask import Flask, render_template, request, redirect, jsonify, url_for, flash, g
from sqlalchemy import create_engine, asc, text
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, User, Item
from flask.ext.httpauth import HTTPBasicAuth
import json
import os

app = Flask(__name__)
auth = HTTPBasicAuth()


# Connect to Database and create database session
engine = create_engine('sqlite:///catelog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


def isLogin():
    return False


def parseJson(arrs, cas):
    Ites = []
    arrsLength = len(arrs)
    casLength = len(cas)
    for x in xrange(arrsLength):
        s = cas[x]
        for y in xrange(len(arrs[x])):
            Ites.append(arrs[x][y]["Title"] + "(" + s + ")")
    return Ites


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
        with open('./static/publicSeed.json') as data_file:
            data = json.load(data_file)
            categories = map(lambda x: x["Name"], data["Category"])
            items = map(lambda x: x["Item"], data["Category"])
            items = parseJson(categories, items)
            return render_template('public.html', categories=categories, items=items)

    categories = session.query(Category.name, User.id).fliter(Category.name == g.user.username).
    filter(Category.user_id == User.id).all()
    user_id = categories.id
    items = session.query(Item.name).filter(Item.user_id == user_id).all()
    return render_template('logedInCata.html', category=categories, item=items)

    # for a in publicCategory:
    #     print(a)


@app.route('/catalog/<name>/Items')
def showItems(name):


@app.route('/catalog/<name>/<item>')
def showSubItems:


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
