from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, BooleanField
from wtforms.validators import Regexp, DataRequired, Length

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(message="Username required")])
    password = StringField('Password', validators=[DataRequired(message="Password required")])
    remember_me = BooleanField()
    signIn = SubmitField('Sign In')

