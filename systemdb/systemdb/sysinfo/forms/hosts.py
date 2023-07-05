from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Regexp

class HostSearchForm(FlaskForm):
    Hostname = StringField('Hostname', validators=[Regexp(regex="^[a-zA-Z0-9 \.\-\_]+$", message="Invalid input")] )
    Domain = StringField('Domain', validators=[Regexp(regex="^[a-zA-Z0-9 \.\-\_]+$", message="Invalid input")] )
    DomainRole = StringField('DomainRole', validators=[Regexp(regex="^[a-zA-Z0-9 \.\-\_]+$", message="Invalid input")] )
    OSVersion = StringField('OSVersion', validators=[Regexp(regex="^[a-zA-Z0-9 \.\-\_]+$", message="Invalid input")] )
    OSBuildNumber = StringField('OSBuildNumber', validators=[Regexp(regex="^[a-zA-Z0-9 \.]+$", message="Invalid input")] )
    OSName = StringField('OSName', validators=[Regexp(regex="^[a-zA-Z0-9 \.\-\_]+$", message="Invalid input")] )
    SystemGroup = StringField('SystemGroup', validators=[Regexp(regex="^[a-zA-Z0-9 \.\-\_]+$", message="Invalid input")] )
    Location = StringField('Location', validators=[Regexp(regex="^[a-zA-Z0-9 \.\-\_]+$", message="Invalid input")] )

    InvertHostname = BooleanField('Invert Hostname')
    InvertDomain = BooleanField('Invert Domain')
    InvertDomainRole = BooleanField('Invert DomainRole')
    InvertOSVersion = BooleanField('Invert OSVersion')
    InvertOSBuildNumber = BooleanField('Invert OSBuildNumber')
    InvertOSName = BooleanField('Invert OSName')
    InvertSystemGroup = BooleanField('Invert SystemGroup')
    InvertLocation = BooleanField('Invert Location')

    search = SubmitField('Search')
    brief = SubmitField('Download Excel (Brief)')
    full = SubmitField('Download Excel (Full)')

