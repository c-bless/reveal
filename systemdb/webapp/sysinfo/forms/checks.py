from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, BooleanField
from wtforms.validators import Regexp

from systemdb.core.regex import RE_SYSINFO_CONFIGCHECK_NAME
from systemdb.core.regex import RE_SYSINFO_CONFIGCHECK_COMPONENT
from systemdb.core.regex import RE_SYSINFO_CONFIGCHECK_METHOD
from systemdb.core.regex import RE_SYSINFO_CONFIGCHECK_KEY
from systemdb.core.regex import RE_SYSINFO_CONFIGCHECK_VALUE
from systemdb.core.regex import RE_SYSINFO_CONFIGCHECK_RESULT
from systemdb.core.regex import RE_SYSINFO_CONFIGCHECK_MESSAGE


class ConfigCheckSearchForm(FlaskForm):
    Name = StringField('Name', validators=[Regexp(regex="^([a-zA-Z0-9 \.\-\_]+)?$", message="Invalid input")])
    Component = StringField('DisplayName',
                              validators=[Regexp(regex="^([a-zA-Z0-9 \.\-\_]+)?$", message="Invalid input")])
    Method = StringField('Method', validators=[Regexp(regex="^([a-zA-Z0-9 \.\-\_]+)?$", message="Invalid input")])
    Key= StringField('Key', validators=[Regexp(regex="^([a-zA-Z0-9 \.\-\_]+)?$", message="Invalid input")])
    Value = StringField('Value', validators=[Regexp(regex="^([a-zA-Z0-9 \.\-\_]+)?$", message="Invalid input")])
    Result = StringField('Result', validators=[Regexp(regex="^([a-zA-Z0-9 \.\-\_]+)?$", message="Invalid input")])
    Message = StringField('Message', validators=[Regexp(regex="^([a-zA-Z0-9 \.\-\_]+)?$", message="Invalid input")])

    InvertName = BooleanField('Invert Name')
    InvertComponent = BooleanField('Invert Component')
    InvertMethod = BooleanField('Invert Method')
    InvertKey = BooleanField('Invert Key')
    InvertValue = BooleanField('Invert Value')
    InvertResult = BooleanField('Invert Result')
    InvertMessage = BooleanField('Invert Message')

    search = SubmitField('Search')
    download = SubmitField('Download Excel')


