from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, BooleanField
from wtforms.validators import Regexp


class LocalAdminSearchForm(FlaskForm):
    Hostname = StringField('Hostname', validators=[Regexp(regex="^([a-zA-Z0-9 \.\-\_]+)?$", message="Invalid input")])
    Domain = StringField('Domain', validators=[Regexp(regex="^([a-zA-Z0-9 \.\-\_]+)?$", message="Invalid input")])
    Username = StringField('Username', validators=[Regexp(regex="^([a-zA-Z0-9 \.\-\_]+)?$", message="Invalid input")] )

    InvertHostname = BooleanField('Invert Hostname')
    InvertDomain = BooleanField('Invert Domain')
    InvertUsername = BooleanField('Invert Username')

    search = SubmitField('Search')
    full = SubmitField('Download Excel (Full)')
