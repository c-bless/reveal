from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Regexp, Optional

from systemdb.core.regex import RE_SYSINFO_SERVICE_STARTNAME
from systemdb.core.regex import RE_SYSINFO_SERVICE_SYSTEMNAME
from systemdb.core.regex import RE_SYSINFO_SERVICE_PATHNAME
from systemdb.core.regex import RE_SYSINFO_SERVICE_DISPLAYNAME
from systemdb.core.regex import RE_SYSINFO_SERVICE_NAME
from systemdb.core.regex import RE_SYSINFO_SERVICE_STARTED
from systemdb.core.regex import RE_SYSINFO_SERVICE_STARTMODE



class ServiceSearchForm(FlaskForm):
    Name = StringField('Name', validators=[Regexp(regex=RE_SYSINFO_SERVICE_NAME, message="Invalid input")])
    DisplayName = StringField('DisplayName',
                              validators=[Regexp(regex=RE_SYSINFO_SERVICE_DISPLAYNAME, message="Invalid input")])
    SystemName = StringField('Systemname',
                             validators=[Regexp(regex=RE_SYSINFO_SERVICE_SYSTEMNAME, message="Invalid input")])
    PathName = StringField('PathName',
                           validators=[Regexp(regex=RE_SYSINFO_SERVICE_PATHNAME, message="Invalid input")])
    Started = StringField('Started', validators=[Regexp(regex=RE_SYSINFO_SERVICE_STARTED, message="Invalid input")])
    StartMode = StringField('StartMode', validators=[Regexp(regex=RE_SYSINFO_SERVICE_STARTMODE, message="Invalid input")])
    StartName = StringField('StartName', validators=[Regexp(regex=RE_SYSINFO_SERVICE_STARTNAME, message="Invalid input")])

    InvertName = BooleanField('Invert Name')
    InvertDisplayName = BooleanField('Invert DisplayName')
    InvertSystemName = BooleanField('Invert SystemName')
    InvertPathName = BooleanField('Invert PathName')
    InvertStartMode = BooleanField('Invert StartMode')
    InvertStartName = BooleanField('Invert StartName')
    search = SubmitField('Search')
    download = SubmitField('Download Excel')


