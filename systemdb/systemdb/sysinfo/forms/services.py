from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Regexp

class ServiceAclSearchForm(FlaskForm):
    User = StringField('User', validators=[DataRequired(message="Data required"),
                                           Regexp(regex="^[a-zA-Z0-9 \.\-\_]+$", message="Invalid input") ]
                       )
    Permission = StringField('Permission', validators=[DataRequired(message="Data required"),
                                           Regexp(regex="^[a-zA-Z0-9 \.\-\_]+$", message="Invalid input") ]
                             )
    InvertUser = BooleanField('Invert User')
    InvertPermission = BooleanField('Invert Permission')
    search = SubmitField('Search')


class ServiceUserContextSearchForm(FlaskForm):
    Startname = StringField('Startname', validators=[DataRequired(message="Data required"),
                                           Regexp(regex="^[a-zA-Z0-9 \.\-\_]+$", message="Invalid input") ]
                       )
    Invert = BooleanField('Invert Startname')
    search = SubmitField('Search')


