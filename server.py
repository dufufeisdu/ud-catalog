#!/usr/bin/env python2
import json
import os
import requests

from flask import Flask, render_template, request, redirect, jsonify, url_for, flash, g, make_response
from flask import session as login_session
from flask_httpauth import HTTPBasicAuth

from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
from apiclient import discovery
import httplib2
from oauth2client import client

from init_database import Base, Category, User, Item
from utilize import *


app = Flask(__name__)
auth = HTTPBasicAuth()
CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']

# Connect to Database and create database session
engine = create_engine('sqlite:///catelog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


def isLogin():
    if 'username' in login_session:
        return True
    else:
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
        items = getItems()
        categories = getCatagory()
        all_items = getAllItems(items, categories)
        return render_template('public.html', categories=categories, items=all_items)

    categories = session.query(Category).filter(
        Category.user_id == login_session.get('user_id', None)).all()
    category = map(lambda x: x.name, categories)
    category_id = map(lambda x: x.id, categories)
    category_length = len(categories)
    items = []
    for i in xrange(category_length):
        s = session.query(Item).filter(
            category_id[i] == Item.cata_id).all()
        item = map(lambda x: {'Title': x.title,
                              'Description': x.description}, s)
        items.append(item)

    all_items = getAllItems(items, category)
    login_session['items'] = items
    login_session['categories'] = category
    return render_template('catalog.html', categories=category, items=all_items)


@app.route('/addItem', methods=['GET', 'POST'])
def addItem():
    if isLogin():
        if request.method == 'GET':
            return render_template('addItems.html', categories=login_session['categories'])
        if request.method == 'POST':
            if isRepeat(request, login_session):
                return render_template('error.html', message="You have created the same item")
            title = request.form.get('title', None)
            description = request.form.get('description', None)
            category = request.form.get('category', None)
            if category not in login_session['categories']:
                new_cate = Category(
                    name=category, user_id=login_session['user_id'])
                session.add(new_cate)
                session.commit()

            cata_id = session.query(Category).\
                filter(Category.user_id == login_session['user_id']).\
                filter(Category.name == category).one().id
            new_item = Item(
                title=title, description=description, cata_id=cata_id)
            session.add(new_item)
            session.commit()
            return redirect(url_for("showCategory"))

    else:
        return render_template('error.html', message="You should log in first")


@app.route('/catagory.json')
def getUserJson():

    if isLogin():
        json_dic = {'category': login_session.get(
            'username', None), 'Category': []}
        user_id = login_session.get('user_id', None)
        categories = session.query(Category).filter_by(
            user_id=Category.user_id).all()
        cate_ids = map(lambda x: x.id, categories)
        cate_names = map(lambda x: x.name, categories)
        for i in xrange(len(cate_ids)):
            items = session.query(Item).filter_by(cata_id=cate_ids[i]).all()
            items = map(
                lambda x: {'Title': x.title, 'Description': x.description}, items)
            json_dic['Category'].append(
                {'name': cate_names[i], 'Item': items})
        return jsonify(json_dic)
    else:
        return render_template('error.html', message="You need login first")


@app.route('/catalog/<category>/Items')
def showItems(category):
    if isLogin():
        categories = login_session['categories']
        items = login_session['items']
        catagory_items = getCatagoryItems(items, categories, category)
        return render_template('catalogSub.html', categories=categories, items=catagory_items)
    else:
        categories = getCatagory()
        items = getItems()
        catagory_items = getCatagoryItems(items, categories, category)
        return render_template('publicSub.html', categories=categories, items=catagory_items)


@app.route('/catalog/<category>/<title>')
def showSubItems(category, title):
    if isLogin():
        categories = login_session['categories']
        items = login_session['items']
        description = getItemDescription(items, categories, category, title)
        return render_template('itemDescriptionLogin.html',
                               category=category, title=title, description=description)
    else:
        categories = getCatagory()
        items = getItems()
        description = getItemDescription(items, categories, category, title)
        return render_template('itemDescription.html', item=category, description=description)


@app.route('/login')
def showLogin():
    state = getSeverState()
    login_session['state'] = state
    return render_template('login.html', STATE=state)


@app.route('/logout')
def showLogout():
    if login_session.get('provider') == 'google':
        return redirect(url_for('gdisconnect'))
    # hold positions for facebook/ twitter/

    # hold position for user sign up
    return render_template('error.html', message="You need login first")


@app.route('/catalog/<category>/<title>/edit', methods=['GET', 'POST'])
def editItems(category, title):
    if isLogin():
        if isRepeat(request, login_session):
            return render_template('error.html', message="You have created the same item")

        categories = login_session['categories']
        items = login_session['items']
        description = getItemDescription(
            items, categories, category, title)
        if request.method == 'GET':
            return render_template('edit.html', categories=categories,
                                   title=title, description=description, category=category)
        else:
            # if user changed the category,
            # delete the item and
            # create a new item on the selected category
            if category != request.form.get('category', None):
                # Delete the category-> Item-> description

                old_item = session.query(Item).\
                    filter(Category.user_id == login_session['user_id']).\
                    filter(Category.name == category).\
                    filter(Item.cata_id == Category.id).\
                    filter(Item.title == title).\
                    filter(Item.description == description).one()
                session.delete(old_item)
                session.commit()

                update_category = session.query(Category).filter(
                    Category.user_id == login_session['user_id']).\
                    filter(Category.name == request.form.get(
                        'category', None)).one()
                new_item = Item(
                    title=request.form['title'], description=request.form['description'],
                    cata_id=update_category.id)
                session.add(new_item)
                session.commit()
                return redirect(url_for("showCategory"))
            # if user change title or description
            # but not the category, update that item
            elif title != request.form.get('title', None) or\
                    description != request.form.get('description', None):
                old_category = session.query(Category).\
                    filter(Category.user_id == login_session['user_id']).\
                    filter(Category.name == category).\
                    one()
                session.query(Item).\
                    filter(Item.cata_id == old_category.id).\
                    filter(Item.title == title).\
                    filter(Item.description == description).update({
                        "title": request.form.get('title', None),
                        "description": request.form.get('description', None)
                    }, synchronize_session=False)
                session.commit()
                return redirect(url_for("showCategory"))
            else:
                return redirect(url_for("showCategory"))
    else:
        return render_template('error.html', message="You need login first")


@app.route('/catalog/<category>/<title>/delete', methods=['GET', 'POST'])
def deleteItems(category, title):
    if isLogin():
        if request.method == 'GET':
            return render_template('delete.html', category=category, title=title)
        if request.method == 'POST':
            item_del = session.query(Item).\
                filter(Category.user_id == login_session['user_id']).\
                filter(Category.id == Item.cata_id).\
                filter(Category.name == category).\
                filter(Item.title == title).one()
            session.delete(item_del)
            session.commit()
            return redirect('/')
    else:
        return render_template('error.html', message="You need login first")


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
        createRawCatalog(user_id, getCatagory())
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


@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        # Reset the user's sesson.
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['picture']
        del login_session['provider']
        del login_session['categories']
        del login_session['items']
        del login_session['user_id']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return render_template('disconnect.html', message="Successfully disconnected")
    else:
        # For whatever reason, the given token was invalid.
        response = make_response(
            json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


def createUser(login_session):
    new_user = User(username=login_session['username'],
                    third_party_id=login_session['gplus_id'], picture=login_session['picture'])
    session.add(new_user)
    session.commit()

    user = session.query(User).filter_by(
        third_party_id=login_session['gplus_id']).one()
    return user.id


def createRawCatalog(user_id, CateList):
    items = getItems()
    categories = getCatagory()
    for cate in CateList:
        new_category = Category(name=cate, user_id=user_id)
        session.add(new_category)
        session.commit()
        new_cate = session.query(Category).\
            filter_by(name=cate).\
            filter_by(user_id=user_id).\
            one()
        cate_id = new_cate.id
        cate_names = new_cate.name
        item_list = getCatagoryItems(items, categories, cate_names)
        for item in item_list:
            description = getItemDescription(
                items, categories, item[1], item[0])
            new_item = Item(
                title=item[0], description=description, cata_id=cate_id)
            session.add(new_item)
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


def isRepeat(request, login_session):
    try:
        category = session.query(Category).\
            filter(Category.user_id == login_session['user_id']).\
            filter(Category.name == request.form.get('category', None)).one()
        session.query(Item).\
            filter(Item.cata_id == category.id).\
            filter(Item.title == request.form.get('title', None)).\
            filter(Item.description == request.form.get(
                'description', None)).one()
        return True
    except:
        return False


if __name__ == '__main__':
    app.secret_key = '\x1a\xbeZ\xb7g\x1f\x00\xfe\x1a|s\x13y\xd8r)(E\x88\xa4go(\xc1'
    app.debug = True
    app.run(host='localhost', port=8000)
