from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, BooleanField
from wtforms.validators import Regexp

from systemdb.core.regex import RE_SYSINFO_DOMAIN
from systemdb.core.regex import RE_SYSINFO_HOSTNAME
from systemdb.core.regex import RE_SYSINFO_USER_NAME



class LocalAdminSearchForm(FlaskForm):
    Hostname = StringField('Hostname', validators=[Regexp(regex=RE_SYSINFO_HOSTNAME, message="Invalid input")])
    Domain = StringField('Domain', validators=[Regexp(regex=RE_SYSINFO_DOMAIN, message="Invalid input")])
    Username = StringField('Username', validators=[Regexp(regex=RE_SYSINFO_USER_NAME, message="Invalid input")] )

    InvertHostname = BooleanField('Invert Hostname')
    InvertDomain = BooleanField('Invert Domain')
    InvertUsername = BooleanField('Invert Username')

    search = SubmitField('Search')
    full = SubmitField('Download Excel (Full)')
