from functools import wraps
from os import environ

from flask import Flask
from flask import request, Response
from flask.ext.security.utils import encrypt_password, verify_password
from flask.ext.sqlalchemy import SQLAlchemy
from flask_restful import Resource, Api

app = Flask(__name__)

app.config.from_object(environ['APP_SETTINGS'])
app.config['SECURITY_PASSWORD_SALT'] = environ.get('SECURITY_PASSWORD_SALT')

api = Api(app)
db = SQLAlchemy(app)

import models


def check_auth(email, password):
    """
    This function is called to check if a username & password combination is valid.
    """
    users_with_that_email = models.User.query.filter_by(email=email)
    db_password = ""
    if users_with_that_email.count() > 0:
        db_password = users_with_that_email[0].password

    return verify_password(password, db_password)


def authenticate():
    """Sends a 401 response that enables basic auth"""
    return Response(
        'Could not verify your access level for that URL.\n'
        'You have to login with proper credentials', 401,
        {'WWW-Authenticate': 'Basic realm="Login Required"'})


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)

    return decorated


class HelloWorld(Resource):
    def get(self):
        return {'hello': 'world'}


class ProtectedResource(Resource):
    """
    This endpoint is protected by basic auth and is only used for testing
    """
    decorators = [requires_auth]

    def get(self):
        return "Hello", 200


class RegisterUser(Resource):
    """
    This endpoint registers a user's email and password, encrypting the latter in the database.
    """
    def post(self):
        email = request.form['email']
        password = encrypt_password(request.form['password'])

        if not is_user_in_db(email):
            models.user_datastore.create_user(email=email, password=password)
            db.session.commit()
            new_user = models.User.query.filter_by(email=email)
            return new_user[0].email, 201

        return email, 406


class RegisterLock(Resource):
    """
    This endpoint registers a lock, associating it with the user's password.
    """

    decorators = [requires_auth]

    def post(self, lock_id):

        email = request.authorization.username
        database_lock_id = models.Lock.query.filter_by(id=lock_id)

        if database_lock_id.count() > 0:
            return lock_id, 406
        else:
            this = models.Lock(id=lock_id, owner=email, locked=True)
            db.session.add(this)
            db.session.commit()
            return lock_id, 200


class OpenLock(Resource):
    """
    This endpoint opens the lock if lockID and associated user is consistent within the database
    """
    decorators = [requires_auth]

    def put(self, lock_id):
        return change_lock_state(lock_id, False)


class CloseLock(Resource):
    """
    This endpoint closes the lock if lockID and associated user is consistent within the database
    """
    decorators = [requires_auth]

    def put(self, lock_id):
        return change_lock_state(lock_id, True)


class LockList(Resource):
    def get(self):
        locks = db.session.query(models.Lock).all()
        lock_json = []
        for lock in locks:
            lock_json.append({"id": lock.id, "locked": lock.locked})
        return lock_json


class LockCheck(Resource):
    """
    This endpoint checks if the lock in the database is to be opened or closed
    """
    decorators = [requires_auth]

    def get(self, lock_id):
        lock_state = False
        if lock_id is not None:
            email = request.authorization.username
            database_lock_id = models.Lock.query.filter_by(id=lock_id).first()

            if database_lock_id is not None:
                if email == database_lock_id.owner:
                    lock_state = database_lock_id.locked

                    if lock_state is False:
                        return lock_state, 200
                    else:
                        return lock_state, 423
                else:
                    return lock_state, 403

        return lock_state, 404




def is_user_in_db(user):
    email = models.User.query.filter_by(email=user)
    if email.count() > 0:
        return True
    else:
        return False


@requires_auth
def change_lock_state(lock_id, new_state):
    if lock_id is not None:
        email = request.authorization.username
        database_lock_id = models.Lock.query.filter_by(id=lock_id).first()

        if database_lock_id is not None:
            if email == database_lock_id.owner:
                database_lock_id.locked = new_state
                db.session.commit()
                return lock_id, 200
            else:
                return lock_id, 401

    return lock_id, 404



# testing endpoints
api.add_resource(HelloWorld, '/')
api.add_resource(ProtectedResource, '/protected-resource')
api.add_resource(LockList, '/lock')

# actual endpoints
api.add_resource(RegisterUser, '/register-user')
api.add_resource(RegisterLock, '/register-lock/', '/register-lock/<int:lock_id>')
api.add_resource(OpenLock, '/open', '/open/<int:lock_id>')
api.add_resource(CloseLock, '/close', '/close/<int:lock_id>')
api.add_resource(LockCheck, '/check', '/check/<int:lock_id>')

if __name__ == '__main__':
    app.run(debug=True)
