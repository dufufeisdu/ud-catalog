from flask import Flask, render_template, request, redirect, jsonify, url_for, flash
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

    categories = session.query(Category.name, User.id).fliter(
        Category.name == g.user.username).filter(Category.user_id == User.id).all()
    user_id = categories.id
    items = session.query(Item.name).filter(Item.user_id == user_id).all()
    return render_template('logedInCata.html', category=categories, item=items)


@app.route('/oauth/<provider>', methods=['POST'])
def login(provider):
    if provide == 'google':
        print('googel')


@app.route('/catalog/<name>/Items')
def showItems(name):
    categories = getCatagory()
    catagoryItems = getCatagoryItems(name)
    return render_template('publicSub.html', categories=categories, items=catagoryItems)


@app.route('/catalog/<name>/<title>')
def showSubItems(name, title):

    description = getItemDescription(name, title)
    return render_template('itemDescription.html', item=name, description=description)


@app.route('/login')
def showLogin():
    state = getSeverState()
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
        response = make_response(json.dumps('Invalid state parameter.'), 401)
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
        print "Token's client ID does not match app's."
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

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    login_session['provider'] = 'google'

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output

def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None

if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='localhost', port=8000)
