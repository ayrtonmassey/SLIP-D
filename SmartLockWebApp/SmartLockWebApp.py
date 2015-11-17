from flask import Flask, render_template, session, flash, request, abort, redirect, url_for, Markup, jsonify
from config import *
from forms import LoginForm, RegisterForm, RegisterLockForm
from base64 import b64encode
from functools import wraps
import json

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.debug = True

from flask_wtf.csrf import CsrfProtect
CsrfProtect(app)

#################################
# ========= Logging =========== #
#################################

import logging
import sys
app.logger.addHandler(logging.StreamHandler(sys.stdout))
app.logger.setLevel(logging.DEBUG)


#################################
# ========= Bootstrap ========= #
#################################

from flask_bootstrap import Bootstrap

Bootstrap(app)


#################################
# ============ API ============ #
#################################

import requests
from requests import ConnectionError


def api_endpoint(endpoint=''):
    return '{}/{}'.format(API_BASE_ADDR,endpoint)


def session_auth_headers():
    if 'username' in session and 'password' in session and session['username'] and session['password']:
        return {
            'Authorization': 'Basic ' + b64encode("{}:{}".format(session['username'], session['password']))
        }
    return None


def auth_headers(username,password):
    return {
        'Authorization': 'Basic ' + b64encode("{}:{}".format(username, password))
    }


def get_user():
    try:
        response = requests.get(api_endpoint('me'),
                                headers=session_auth_headers())
        if response.status_code == 200:
            data = json.loads(response.text)
            return data
        else:
            flash('Could not retreive user data: Status {}. Please try again later.'.format(response.status_code), 'warning')
    except ConnectionError as ex:
        flash('Could not retreive list of locks. Please try again later.', 'warning')
        
    return None    


def get_locks():
    try:
        response = requests.get(api_endpoint('lock'),
                                headers=session_auth_headers())
        if response.status_code == 200:
            data = json.loads(response.text)
            return data
        else:
            flash('Could not retreive list of locks: Status {}. Please try again later.'.format(response.status_code), 'warning')
    except ConnectionError as ex:
        flash('Could not retreive list of locks. Please try again later.', 'warning')
        
    return None


#################################
# =========== Views =========== #
#################################

def lock_required(function):
    @wraps(function)
    def decorated_function(*args, **kwargs):
        if get_locks():
            return function(*args, **kwargs)
        else:
            flash('You must own a lock to access that page.','danger')
            return redirect(url_for('profile'))
    return decorated_function


def lock_prohibited(function):
    @wraps(function)
    def decorated_function(*args, **kwargs):
        if not get_locks():
            return function(*args, **kwargs)
        else:
            flash('You must not own a lock to access that page.','danger')
            return redirect(url_for('profile'))
    return decorated_function


def login_required(function):
    @wraps(function)
    def decorated_function(*args, **kwargs):
        if 'username' in session and 'password' in session and session['username'] and session['password']:
            return function(*args, **kwargs)
        else:
            flash('You need to be logged in to access that page.','danger')
            return redirect(url_for('login', next=url_for(function.__name__)))
    return decorated_function


def login_prohibited(function):
    @wraps(function)
    def decorated_function(*args, **kwargs):
        if 'username' in session and 'password' in session and session['username'] and session['password']:
            flash('Please log out to access that page.','danger')
            return redirect(url_for('profile'))
        else:
            return function(*args, **kwargs)
    return decorated_function


@app.route('/')
def index():
    return render_template('index.htm', app_name=APP_NAME, page='Home')


@app.route('/open/<lock_id>', methods=['PUT'])
@login_required
def open(lock_id):
    response = requests.put(api_endpoint('open/{}'.format(lock_id)),
                        headers=session_auth_headers())
    return (response.text, response.status_code, response.headers.items())


@app.route('/close/<lock_id>', methods=['PUT'])
@login_required
def close(lock_id):
    response = requests.put(api_endpoint('close/{}'.format(lock_id)),
                        headers=session_auth_headers())

    return (response.text, response.status_code, response.headers.items())


@app.route('/status/<lock_id>', methods=['GET'])
@login_required
def status(lock_id):
    # response = requests.get(api_endpoint('status/{}'.format(lock_id)),
    #                     headers=session_auth_headers())
    # return (response.text, response.status_code, response.headers.items())
    return jsonify({
            'locked' : True,
            'pending': True,
    })
    

@app.route('/profile')
@login_required
def profile():
    user_info = get_user()
    lock_info = sorted(get_locks(), key=lambda k: k['id'])
    if not lock_info:
        flash(Markup('You don\'t have any locks yet. If you own a lock, click <a href="/profile/register-lock" class="alert-link">here</a> to register it.'), 'info')
    return render_template('profile.htm', app_name=APP_NAME, page='Home', user_info=user_info, lock_info=lock_info)


@app.route('/profile/register-lock', methods=['GET','POST'])
@login_required
def register_lock():
    form = RegisterLockForm(request.form)
    # Validate inputs
    if form.validate_on_submit():
        # Make a new database record
        try:
            response = requests.post(api_endpoint('lock'),
                                     data={'lock_id'  : form.lock_id.data,
                                           'lock_name': form.lock_name.data},
                                     headers=session_auth_headers())
            
            if response.status_code == 201:
                flash('Registered lock {} successfully!'.format(form.lock_id.data),'success')
                return redirect(url_for('profile'))
            elif response.status_code == 406:
                flash('That lock ID is already registered to another user. Please check your lock ID and try again.', 'danger')
            else:
                flash('Status {}: Registration failed, please try again later.'.format(response.status_code), 'danger')
        except ConnectionError as ex:
            flash('Failed to connect to registration server. Please try again later.', 'danger')

    return render_template('register_lock.htm', app_name=APP_NAME, page='Register Lock', form=form)


@app.route('/login', methods=['GET', 'POST'])
@login_prohibited
def login():
    form = LoginForm()
    
    if form.validate_on_submit():
        try:
            response = requests.get(
                api_endpoint('protected-resource'),
                headers=auth_headers(form.email.data, form.password.data)
            )
            
            if response.status_code == 200:

                flash('Logged in successfully.','success')

                session['username']   = form.email.data
                session['password']   = form.password.data

                next = request.args.get('next')
                # next_is_valid should check if the user has valid
                # permission to access the `next` url
                # if not next_is_valid(next):
                #     return abort(400)

                return redirect(next or url_for('profile'))

            else:
                flash('Login failed. Ensure your e-mail and password are correct and try again.','danger')
        except ConnectionError as ex:
            flash('Failed to connect to login server. Please try again later.', 'danger')
    return render_template('login.html', app_name=APP_NAME, page='Login', form=form)


@app.route('/register', methods=['GET', 'POST'])
@login_prohibited
def register():
    form = RegisterForm(request.form)
    
    if form.validate_on_submit():
        try:
            response = requests.post(api_endpoint('user'),
                                    data={'email'     : form.email.data,
                                          'password'  : form.password.data,
                                          'first_name': form.first_name.data,
                                          'last_name' : form.last_name.data,
                                    }
            )
                
            if response.status_code == 201:
                
                flash('Registered {} successfully! Please log in to continue.'.format(form.email.data),'success')
                
                next = request.args.get('next')
                # next_is_valid should check if the user has valid
                # permission to access the `next` url
                # if not next_is_valid(next):
                #     return abort(400)
                
                return redirect(next or url_for('login'))
            
            elif response.status_code == 406:
                flash('E-mail address already registered, please use a different e-mail address.', 'danger')
            else:
                flash('Status {}: Registration failed, please try again later.'.format(response.status_code), 'danger')
        except ConnectionError as ex:
            flash('Failed to connect to registration server. Please try again later.', 'danger')


    return render_template('register.htm', app_name=APP_NAME, page='Register', form=form)


@app.route('/logout')
def logout():
    session.pop('username',None)
    session.pop('password',None)
    return redirect(url_for('index'))


###########################
# ======== Start ======== #
###########################

if __name__ == '__main__':
    app.run(port=8000)
