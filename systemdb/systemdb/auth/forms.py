from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, BooleanField, PasswordField
from wtforms.validators import Regexp, DataRequired, Length, EqualTo

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(message="Username required")])
    password = StringField('Password', validators=[DataRequired(message="Password required")])
    remember_me = BooleanField()
    signIn = SubmitField('Sign In')


class ChangePasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[
        DataRequired(message="Password required"),
        Length(15, 256),
        Regexp(regex='^([a-zA-Z0-9\.\-\_]+)?$', message="Invalid input")
    ])
    password2 = PasswordField('Confirm Password', validators=[
        DataRequired(message="Password required"),
        Length(15, 256),
        Regexp(regex='^([a-zA-Z0-9\.\-\_]+)?$', message="Invalid input"),
        EqualTo(fieldname="password")
    ])

    submit = SubmitField('Submit')