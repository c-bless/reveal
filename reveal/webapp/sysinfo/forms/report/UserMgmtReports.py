from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, BooleanField, SelectField
from wtforms.validators import Regexp, Optional

from reveal.core.regex import RE_SYSINFO_SYSTEMGROUP
from reveal.core.regex import RE_SYSINFO_LOCATION
from reveal.core.regex import RE_SYSINFO_DOMAIN
from reveal.core.regex import RE_SYSINFO_HOSTNAME
from reveal.core.regex import RE_SYSINFO_USER_NAME

class DirectAssignmentReportForm(FlaskForm):
    SystemGroup = StringField('SystemGroup', validators=[Regexp(regex=RE_SYSINFO_SYSTEMGROUP, message="Invalid input")] )
    Location = StringField('Location', validators=[Regexp(regex=RE_SYSINFO_LOCATION, message="Invalid input")] )

    InvertSystemGroup = BooleanField('Invert SystemGroup')
    InvertLocation = BooleanField('Invert Location')

    search = SubmitField('Search')
    excel = SubmitField('Excel')
    #TemplateFile = SelectField('Template (Word)')
    #word = SubmitField('Word')


class HostByLocalUserSearchForm(FlaskForm):
    SystemGroup = StringField('SystemGroup', validators=[Regexp(regex=RE_SYSINFO_SYSTEMGROUP, message="Invalid input")])
    Location = StringField('Location', validators=[Regexp(regex=RE_SYSINFO_LOCATION, message="Invalid input")])

    InvertSystemGroup = BooleanField('Invert SystemGroup')
    InvertLocation = BooleanField('Invert Location')

    Name = StringField('Local User', validators=[Optional(),
                                                 Regexp(regex=RE_SYSINFO_HOSTNAME, message="Invalid input")] )

    search = SubmitField('Search')
    excel = SubmitField('Excel (Hosts)')
    #TemplateFile = SelectField('Template (Word)')
    #word = SubmitField('Word')


class LocalAdminSearchForm(FlaskForm):
    Hostname = StringField('Hostname', validators=[Regexp(regex=RE_SYSINFO_HOSTNAME, message="Invalid input")])
    Domain = StringField('Domain', validators=[Regexp(regex=RE_SYSINFO_DOMAIN, message="Invalid input")])
    Username = StringField('Username', validators=[Regexp(regex=RE_SYSINFO_USER_NAME, message="Invalid input")])

    InvertHostname = BooleanField('Invert Hostname')
    InvertDomain = BooleanField('Invert Domain')
    InvertUsername = BooleanField('Invert Username')

    SystemGroup = StringField('SystemGroup', validators=[Regexp(regex=RE_SYSINFO_SYSTEMGROUP, message="Invalid input")])
    Location = StringField('Location', validators=[Regexp(regex=RE_SYSINFO_LOCATION, message="Invalid input")])

    InvertSystemGroup = BooleanField('Invert SystemGroup')
    InvertLocation = BooleanField('Invert Location')


    search = SubmitField('Search')
    excel = SubmitField('Download Excel (Full)')
    TemplateFile = SelectField('Template (Word)')
    word = SubmitField('Word')


class LocalGroupMemberSearchForm(FlaskForm):
    SystemGroup = StringField('SystemGroup', validators=[Regexp(regex=RE_SYSINFO_SYSTEMGROUP, message="Invalid input")])
    Location = StringField('Location', validators=[Regexp(regex=RE_SYSINFO_LOCATION, message="Invalid input")])

    InvertSystemGroup = BooleanField('Invert SystemGroup')
    InvertLocation = BooleanField('Invert Location')


    search = SubmitField('Search')
    excel = SubmitField('Download Excel (Full)')
    TemplateFile = SelectField('Template (Word)')
    word = SubmitField('Word')