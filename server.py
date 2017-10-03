from flask import Flask, render_template, request, redirect, jsonify, url_for, flash, g
from flask import session as login_session
from sqlalchemy import create_engine, asc, text
from sqlalchemy.orm import sessionmaker
from init_database import Base, Category, User, Item
from flask_httpauth import HTTPBasicAuth
from flask import make_response
from utilize import *
import json
import os
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
from apiclient import discovery
import httplib2
from oauth2client import client
import requests

app = Flask(__name__)
auth = HTTPBasicAuth()
CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "practice"

# Connect to Database and create database session
engine = create_engine('sqlite:///catelog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


def isLogin():
    try:
        login_session['username']
        return True
    except:
        KeyError
        return False


@auth.verify_password
def verify_password(username, password):
    user = session.query(User).filter_by(username=username).first()
    if not user:
        print("User not found")
        return False
    elif not user.verify_password(password):
        print("Unable to verfy password")
        return False
    else:
        g.user = user
        return True


@app.route('/')
def showCategory():
    if isLogin() is False:
        # user_id 1 is the reserved public resource
        items = getItems()
        categories = getCatagory()
        allItems = getAllItems(items, categories)
        return render_template('public.html', categories=categories, items=allItems)

    dbUserId = session.query(User.id).filter_by(
        username=login_session['username']).one()
    dbUserId = dbUserId[0]
    categories = session.query(Category).filter(
        Category.user_id == dbUserId).all()
    categoryName = map(lambda x: x.name, categories)
    categoryId = map(lambda x: x.id, categories)
    categoryLength = len(categories)
    items = []
    for i in xrange(categoryLength):
        s = session.query(Item).filter(
            categoryId[i] == Item.cata_id).all()
        item = map(lambda x: {'Title': x.title,
                              'Description': x.description}, s)
        items.append(item)

    allItems = getAllItems(items, categoryName)
    return render_template('catalog.html', categories=categoryName, items=allItems)


@app.route('/addItem')
def addItem():
    try:
        if login_session['username'] is not None:
            return render_template()
    except KeyError:
        return render_template('error.html', message="You should log in first")


@app.route('/oauth/<provider>', methods=['POST'])
def login(provider):
    if provide == 'google':
        print('google')


@app.route('/<username>/catagory.json')
def getUserJson(username):

    if login_session['username'] is not None:
        jsonDic = {'Name': username, 'Category': []}
        user_id = session.query(User.id).filter_by(
            username=username).one()
        user_id = user_id[0]
        categories = session.query(Category).filter_by(
            user_id=Category.user_id).all()
        cateIDs = map(lambda x: x.id, categories)
        cateName = map(lambda x: x.name, categories)
        for i in xrange(len(cateIDs)):
            Items = session.query(Item).filter_by(cata_id=cateIDs[i]).all()
            Items = map(
                lambda x: {'Title': x.title, 'Description': x.description}, Items)
            jsonDic['Category'].append({'Name': cateName[i], 'Item': Items})
        return jsonify(jsonDic)

    return "You are not log in"


@app.route('/catalog/<name>/Items')
def showItems(name):
    categories = getCatagory()
    items = getItems()
    catagoryItems = getCatagoryItems(items, categories, name)
    return render_template('publicSub.html', categories=categories, items=catagoryItems)


@app.route('/catalog/<name>/<title>')
def showSubItems(name, title):
    categories = getCatagory()
    items = getItems()
    description = getItemDescription(items, categories, name, title)
    return render_template('itemDescription.html', item=name, description=description)


@app.route('/login')
def showLogin():
    state = getSeverState()
    login_session['state'] = state
    return render_template('login.html', STATE=state)


@app.route('/catalog/<name>/edit')
def editItems(name):
    return 'edit'


@app.route('/catalog/<name>/delete')
def deleteItems(name):
    return 'delete'


@app.route('/gconnect', methods=['POST'])
def gconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps(
            'Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    code = request.data
    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response
# Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()
    login_session['username'] = data['email']
    login_session['picture'] = data['picture']
    login_session['provider'] = 'google'

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(login_session['gplus_id'])
    if not user_id:
        user_id = createUser(login_session)
        createRawCatelog(user_id, getCatagory())
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    return output


def createUser(login_session):
    newUser = User(username=login_session['username'], third_party_id=login_session['gplus_id'],
                   picture=login_session['picture'])
    session.add(newUser)
    session.commit()

    user = session.query(User).filter_by(
        third_party_id=login_session['gplus_id']).one()
    return user.id


def createRawCatelog(user_id, CateList):
    items = getItems()
    categories = getCatagory()
    for cate in CateList:
        newCateLog = Category(name=cate, user_id=user_id)
        session.add(newCateLog)
        session.commit()
        newCate = session.query(Category).filter_by(name=cate).one()
        cateId = newCate.id
        cateName = newCate.name
        itemList = getCatagoryItems(items, categories, cateName)
        for item in itemList:
            description = getItemDescription(
                items, categories, item[1], item[0])
            newItem = Item(
                title=item[0], description=description, cata_id=cateId)
            session.add(newItem)
            session.commit()


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(g_id):
    try:
        user = session.query(User).filter_by(third_party_id=g_id).one()
        return user.id
    except:
        return None


if __name__ == '__main__':
    app.secret_key = '\x1a\xbeZ\xb7g\x1f\x00\xfe\x1a|s\x13y\xd8r)(E\x88\xa4go(\xc1'
    app.debug = True
    app.run(host='localhost', port=8000)
