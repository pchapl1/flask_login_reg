import os
import sys
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine, and_ , or_ ,text 
from flask import Flask, render_template, request, redirect, url_for, session
import re
import bcrypt
from db import *

app = Flask(__name__)
app.secret_key = 'dev'


@app.route('/home')
def home():
    username = session['username']
    if username:
        print(username)
        print(id)
        return render_template('index.html', id = id)
    return f'You do not have permission to access this page'


@app.route('/', methods = ['Get','POST'])
@app.route('/login', methods = ['Get','POST'])
def login():

    sql_session = start_session()
    msg = ''
    # print(request.form)
    
    if request.method == 'POST' and len(request.form['username'])>0 and len(request.form['password']) > 0:
        session.pop('msg', None)
        form_username = request.form['username']
        form_password = request.form['password']
        user = sql_session.query(User).filter(User.username == form_username).first()

        
        if user and user.login_attempts > 0 and  bcrypt.checkpw(form_password.encode('utf-8'), user.password):
            msg = 'Logged in successfully'
            session['loggedin'] = True
            session['username'] = form_username
            session['id'] = user.id
            user.login_attempts = 5
            sql_session.commit()
            return redirect('/home')
        else:
            user.login_attempts -= 1

            sql_session.commit()


            msg = f'invalid username or password, please try again.  your account will be locked after {user.login_attempts} more attempts'
            if user.login_attempts < 1:
                user.account_locked = True
                msg = 'too many attempts.  account is locked'
            return render_template('login.html', msg = msg)
    return render_template('login.html', msg=msg)
    


@app.route('/logout')
def logout():

    [session.pop(key) for key in list(session.keys())]
    # sql_session = start_session()
    # session.pop('loggedin',None)
    # session.pop('id',None)
    # session.pop('username',None)
    # session.pop('msg', None)
    return redirect(url_for('login'))


@app.route('/register-page')
def display_register():
    sql_session = start_session()
    return render_template('register.html')


@app.route('/register', methods = ['GET', 'POST'])
def register():
    sql_session = start_session()
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form:
        form_username = request.form['username']
        form_password = request.form['password']
        salt = bcrypt.gensalt()
        hashed_pw = bcrypt.hashpw(form_password.encode('utf-8'), salt)
        form_email = request.form['email']

        user = sql_session.query(User).filter(User.username == form_username).first()
        if user:
            msg = "Username already exists, please try again"
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', form_email):
            msg = 'invalid email address'
        elif not re.match(r'[A-Za-z0-9]+', form_username):
            msg = 'username must contain only characters and numbers you goon'
        elif not form_username or not form_password or not form_email:
            msg = 'well jeez, you gotta fill out all the fields if you want to play this game buddy'
        else:
            new_user = User(username = form_username, password = hashed_pw, email = form_email)
            sql_session.add(new_user)
            sql_session.commit()

            msg = 'successfully registered guy'
            return render_template('register.html', msg = msg)
        return render_template('register.html', msg= msg)
    return render_template('register.html')

# -----------Resetting Password------------------------

@app.route('/reset_password', methods = ['Get', 'POST'])
def reset_password():
    sql_session = start_session()
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:

        form_username = request.form['username']
        new_form_password = request.form['password']
        user = sql_session.query(User).filter(User.username == form_username).first()
        salt = bcrypt.gensalt()
        hashed_pw = bcrypt.hashpw(new_form_password.encode('utf-8'), salt)
        user.password = hashed_pw
        sql_session.commit()
        msg = 'password succesfully changed'
        session['msg'] = msg
        return redirect(url_for('login'))
    return render_template('reset_password.html', msg = msg)


# app.run(debug=True)