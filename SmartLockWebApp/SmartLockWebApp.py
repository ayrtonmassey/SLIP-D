from flask import Flask, render_template, session, flash, request, abort, redirect, url_for, Markup, jsonify
from werkzeug.exceptions import BadRequest
from config import *
from forms import LoginForm, RegisterForm, RegisterLockForm
from base64 import b64encode
from functools import wraps
import json

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.debug = True

from flask_wtf.csrf import CsrfProtect
csrf = CsrfProtect(app)

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


######################################
# =========== Decorators =========== #
######################################

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


#################################
# ======== Endpoints ========== #
#################################


@app.route('/friend_search_data')
@login_required
def friend_search_data():
    lock_id = request.args.get('lock_id',None)
    if lock_id:
        u_l_response = requests.get(api_endpoint('user?lock_id={}'.format(lock_id)),
                              headers=session_auth_headers())
        user_lock_data = u_l_response.text

    u_response = requests.get(api_endpoint('user'),
                              headers=session_auth_headers())

    user_data = u_response.text
    if u_response.status_code == 200:
        user_data = json.loads(user_data)

        user_data = map(lambda u: dict(u,**{
            'is_self': u['email'] == session['username'],
            'name': '{} {}'.format(u['first_name'],u['last_name'])
        }),user_data)

        is_friend = request.args.get('is_friend',None)
        if is_friend is not None:
            is_friend = not(is_friend in ['False','false','0'])
            user_data = filter(lambda u: u['is_friend'] == is_friend,user_data)
        
        is_self = request.args.get('is_self',None)
        if is_self is not None:
            is_self = not(is_self in ['False','false','0'])
            user_data = filter(lambda u: u['is_self'] == is_self,user_data)            

        if lock_id:
            if u_l_response.status_code == 200:
                user_lock_data = json.loads(user_lock_data)
                lock_user_ids = [ user['id'] for user in user_lock_data ]
                user_data = map(lambda u: dict(u,**{'has_access': (u['id'] in lock_user_ids) }), user_data)
                filter_access = request.args.get('has_access',None)
                if filter_access is not None:
                    filter_access = not(filter_access in ['False','false','0'])
                    user_data = filter(lambda u: u['has_access'] == filter_access,user_data)
            else:
                return json.dumps({'detail': 'Error loading lock data.'}), 404, {'Content-Type': 'application/json'}
            
        return json.dumps(user_data,indent=4,sort_keys=True), 200, {'Content-Type': 'application/json'}
    else:
        return json.dumps({'detail': 'Error loading friend and/or user data.'}), 404, {'Content-Type': 'application/json'}


@app.route('/friend', methods=['POST','PUT'])
@login_required
def friend():
    data = dict(request.form)
    data.pop('csrf_token')
    if request.form['_method'] == 'POST':
        response = requests.post(api_endpoint('friend'),
                                 data=data,
                                 headers=session_auth_headers())
    if request.form['_method'] == 'DELETE':
        response = requests.delete(api_endpoint('friend'),
                                   params=data,
                                   data=data,
                                   headers=session_auth_headers())

    next = request.args.get('next')
    # next_is_valid should check if the user has valid
    # permission to access the `next` url
    # if not next_is_valid(next):
    #     return abort(400)
    return redirect(next or url_for('friends'))


@app.route('/friend_lock', methods=['POST','DELETE'])
@login_required
def friend_lock():
    data = dict(request.form)
    data.pop('csrf_token')
    if request.form['_method'] == 'POST':
        response = requests.post(api_endpoint('friend-lock'),
                                 data=data,
                                 headers=session_auth_headers())
        if response.status_code != 201:
            flash('Status {}: Error adding friend to lock, please try again later.'.format(response.status_code),'danger')
    elif request.form['_method'] == 'DELETE':
        response = requests.delete(api_endpoint('friend-lock'),
                                   params=data,
                                   data=data,
                                   headers=session_auth_headers())
        if response.status_code != 200:
            flash('Status {}: Error adding friend to lock, please try again later.'.format(response.status_code),'danger')

    next = request.args.get('next')
    # next_is_valid should check if the user has valid
    # permission to access the `next` url
    # if not next_is_valid(next):
    #     return abort(400)
    return redirect(next or url_for('profile'))


@app.route('/open/<lock_id>', methods=['POST', 'PUT'])
@login_required
def open(lock_id):
    response = requests.put(api_endpoint('open/{}'.format(lock_id)),
                        headers=session_auth_headers())
    return (response.text, response.status_code, response.headers.items())

csrf.exempt(open)


@app.route('/close/<lock_id>', methods=['POST', 'PUT'])
@login_required
def close(lock_id):
    response = requests.put(api_endpoint('close/{}'.format(lock_id)),
                        headers=session_auth_headers())
    return (response.text, response.status_code, response.headers.items())

csrf.exempt(close)


@app.route('/status/<lock_id>', methods=['GET'])
@login_required
def status(lock_id):
    response = requests.get(api_endpoint('lock/{}'.format(lock_id)),
                        headers=session_auth_headers())
    return (response.text, response.status_code, response.headers.items())


#################################
# =========== Views =========== #
#################################

@app.route('/')
def index():
    return render_template('index.htm', app_name=APP_NAME, page='Home')


@app.route('/profile', methods=['GET','POST'])
@login_required
def profile():
    if request.method == 'POST':
        friend_id = request.form.get('friend_id',None)
        if friend_id is not None:
            return redirect(url_for('user_profile',user_id=friend_id))
        else:
            raise BadRequest('No data')
    else:
        user_info = get_user()
        return render_template('profile.htm', app_name=APP_NAME, page=session['username'], user_info=user_info)


@app.route('/profile/<user_id>')
@login_required
def user_profile(user_id):
    # Redirect to /profile if we're looking at the logged in user
    if (int(user_id) == session['user']['id']):
        return redirect(url_for('profile'))

    # Else collect user data:
    u_response = requests.get(api_endpoint('user/{}'.format(user_id)),
                            headers=session_auth_headers())
    user_info = u_response.text

    # If the user exists,
    if u_response.status_code == 200:
        # Render their profile.
        user_info = json.loads(user_info)
        return render_template('user_profile.htm', app_name=APP_NAME, page='{} {}'.format(user_info['first_name'],user_info['last_name']), user_info=user_info)
    else:
        flash('Status {}: Could not retrieve user data, please try again later.'.format(u_response.status_code),'danger')
        return redirect(url_for('index'))


@app.route('/locks/register', methods=['GET','POST'])
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


@app.route('/friends')
@login_required
def friends():
    response = requests.get(api_endpoint('friend'),
                              headers=session_auth_headers())
    friends = None
    if response.status_code == 200:
        friends = json.loads(response.text)
    else:
        flash('Could not retreive list of friends: Status {}. Please try again later.'.format(response.status_code), 'warning')
    return render_template('friends.htm', app_name=APP_NAME, page='Friends', friends=friends)


@app.route('/locks')
@login_required
def locks():
    lock_info = get_locks()
    if not lock_info:
        flash(Markup('You don\'t have any locks yet. If you own a lock, click <a href="/locks/register" class="alert-link">here</a> to register it.'), 'info')
    else:
        lock_info = sorted(lock_info, key=lambda k: k['id'])
    return render_template('locks.htm', app_name=APP_NAME, page='Locks', lock_info=lock_info)


@app.route('/locks/<lock_id>')
@login_required
def lock(lock_id):
    l_response = requests.get(api_endpoint('lock/{}'.format(lock_id)),
                              headers=session_auth_headers())
    client = app.test_client()
    lock_info = json.loads(l_response.text)
    user_info = sorted(lock_info['friends'], key=lambda k: {True: '', False: k['name']}[lock_info['owner_id']==k['id']])
    return render_template('lock.htm', app_name=APP_NAME, page='Lock: {}'.format(lock_info['name']), user_info=user_info, lock_info=lock_info)


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

                session['username'] = form.email.data
                session['password'] = form.password.data
                session['user']     = get_user()

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
    return render_template('login.html', app_name=APP_NAME, page='Log In', form=form)


@app.route('/logout')
def logout():
    session.pop('username',None)
    session.pop('password',None)
    return redirect(url_for('index'))


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


###########################
# ======== Start ======== #
###########################

if __name__ == '__main__':
    app.run(port=8000)
