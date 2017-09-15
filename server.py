from flask import Flask, render_template, request, redirect, jsonify, url_for, flash
app = Flask(__name__)

from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, User, Item


# Connect to Database and create database session
engine = create_engine('sqlite:///catelog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


@app.route('/')
def showPublicCategory():
    publicCategory = session.query(User, Category).
    filter(User.id == Category.user_id).
    filter(User.name == 'public').all()
    return render_template('public.html', category=publicCategory)
