from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, BooleanField, PasswordField
from wtforms.validators import Regexp, DataRequired, Length, EqualTo
from systemdb.core.regex import RE_AUTH_PASSWORD
from systemdb.core.regex import RE_AUTH_USERNAME


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(message="Username required"),
                           Regexp(regex=RE_AUTH_USERNAME, message="Invalid input")])
    password = StringField('Password', validators=[DataRequired(message="Password required"),
                           Regexp(regex=RE_AUTH_PASSWORD, message="Invalid input")])
    remember_me = BooleanField()
    signIn = SubmitField('Sign In')


class ChangePasswordForm(FlaskForm):
    current_pw = PasswordField('Old Password', validators=[
        DataRequired(message="Password required"),
        Length(15, 256),
        Regexp(regex=RE_AUTH_PASSWORD, message="Invalid input")
    ])
    new_pw = PasswordField('New Password', validators=[
        DataRequired(message="Password required"),
        Length(15, 256),
        Regexp(regex=RE_AUTH_PASSWORD, message="Invalid input")
    ])
    new_pw2 = PasswordField('Confirm New Password', validators=[
        DataRequired(message="Password required"),
        Length(15, 256),
        Regexp(regex=RE_AUTH_PASSWORD, message="Invalid input"),
        EqualTo(fieldname="new_pw", message="Password and password2 do not match")
    ])

    submit = SubmitField('Submit')
