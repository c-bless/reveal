from flask_wtf import FlaskForm

from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, Regexp

class ServiceAclSearchForm(FlaskForm):
    User = StringField('User', validators=[DataRequired(message="Data required"),
                                           Regexp(regex="^[a-zA-Z0-9 \.\-\_]+$", message="Invalid input") ]
                       )
    Permission = StringField('Permission', validators=[DataRequired(message="Data required"),
                                           Regexp(regex="^[a-zA-Z0-9 \.\-\_]+$", message="Invalid input") ]
                             )
    search = SubmitField('Search')


