from flask.ext.wtf import Form
from wtforms import TextField, PasswordField, SubmitField, IntegerField, validators

class LoginForm(Form):
    email = TextField('E-mail Address', [validators.Required(),validators.Email(message=u"Invalid E-mail Address.")])
    password = PasswordField('Password', [validators.Required()])
    submit = SubmitField('Log In')


class RegisterForm(Form):
    # E-mail Fields
    email = TextField('E-mail Address', [validators.Required(),
                                         validators.Email(message=u'Invalid e-mail address.'),
                                         validators.EqualTo('confirm_email', message=u'E-mail addresses do not match.')]
    )
    confirm_email = TextField('Confirm E-mail Address', [validators.Required(),
                                                         validators.Email(message=u'Invalid e-mail address')]
    )
    
    # Password Fields
    password = PasswordField('Password', [validators.Required(),
                                          validators.EqualTo('confirm_password', message=u'Passwords do not match.')]
    )
    confirm_password = PasswordField('Confirm Password', [validators.Required()])

    submit = SubmitField('Register')


class RegisterLockForm(Form):
    lock_id = IntegerField('Lock ID', [validators.Required()])
    
    submit = SubmitField('Register')
