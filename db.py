import os
import sys
from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine, and_ , or_ ,text 
from sqlalchemy.orm import sessionmaker
from sqlalchemy.sql.sqltypes import Boolean
# from flask import Flask, render_template, request, redirect, url_for, session

Base = declarative_base()
engine = create_engine('sqlite:///sqlalchemy_test.db')
class User(Base):
    __tablename__ = 'users'  
    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(250), nullable=False)
    password = Column(String(60), nullable=False)
    email = Column(String(100), nullable=False)
    login_attempts = Column(Integer, default=5)
    account_locked = Column(Boolean, default= False)


Base.metadata.create_all(engine)
# Base.metadata.bind(engine)

def start_session():
    Base.metadata.bind = engine
    DBSession = sessionmaker(bind=engine)
    session = DBSession()       
    return session


