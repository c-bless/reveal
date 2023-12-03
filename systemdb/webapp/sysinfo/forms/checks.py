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
from systemdb.core.regex import RE_SYSINFO_FILENAME

from systemdb.core.regex import RE_SYSINFO_REGISTRYCHECK_EXPECTED
from systemdb.core.regex import RE_SYSINFO_REGISTRYCHECK_NAME
from systemdb.core.regex import RE_SYSINFO_REGISTRYCHECK_CATEGORY
from systemdb.core.regex import RE_SYSINFO_REGISTRYCHECK_CURRENTVALUE
from systemdb.core.regex import RE_SYSINFO_REGISTRYCHECK_DESCRIPTION
from systemdb.core.regex import RE_SYSINFO_REGISTRYCHECK_PATH
from systemdb.core.regex import RE_SYSINFO_REGISTRYCHECK_TAGS
from systemdb.core.regex import RE_SYSINFO_REGISTRYCHECK_KEY
from systemdb.core.regex import RE_SYSINFO_HOSTNAME
from systemdb.core.regex import RE_SYSINFO_SYSTEMGROUP


class ConfigCheckSearchForm(FlaskForm):
    Name = StringField('Name', validators=[Regexp(regex=RE_SYSINFO_CONFIGCHECK_NAME, message="Invalid input")])
    Component = StringField('Component',
                              validators=[Regexp(regex=RE_SYSINFO_CONFIGCHECK_COMPONENT, message="Invalid input")])
    Method = StringField('Method', validators=[Regexp(regex=RE_SYSINFO_CONFIGCHECK_METHOD, message="Invalid input")])
    Key= StringField('Key', validators=[Regexp(regex=RE_SYSINFO_CONFIGCHECK_KEY, message="Invalid input")])
    Value = StringField('Value', validators=[Regexp(regex=RE_SYSINFO_CONFIGCHECK_VALUE, message="Invalid input")])
    Result = StringField('Result', validators=[Regexp(regex=RE_SYSINFO_CONFIGCHECK_RESULT, message="Invalid input")])
    Message = StringField('Message', validators=[Regexp(regex=RE_SYSINFO_CONFIGCHECK_MESSAGE, message="Invalid input")])

    Host = StringField('Host', validators=[Regexp(regex=RE_SYSINFO_HOSTNAME, message="Invalid input")])

    InvertName = BooleanField('Invert Name')
    InvertComponent = BooleanField('Invert Component')
    InvertMethod = BooleanField('Invert Method')
    InvertKey = BooleanField('Invert Key')
    InvertValue = BooleanField('Invert Value')
    InvertResult = BooleanField('Invert Result')
    InvertMessage = BooleanField('Invert Message')
    InvertHost = BooleanField('Invert Host')

    search = SubmitField('Search')
    download = SubmitField('Download Excel')


class RegistryCheckSearchForm(FlaskForm):
    Name = StringField('Name', validators=[Regexp(regex=RE_SYSINFO_REGISTRYCHECK_NAME, message="Invalid input")])
    Category = StringField('Category',
                              validators=[Regexp(regex=RE_SYSINFO_REGISTRYCHECK_CATEGORY, message="Invalid input")])
    Description = StringField('Description', validators=[Regexp(regex=RE_SYSINFO_REGISTRYCHECK_DESCRIPTION, message="Invalid input")])
    Tags= StringField('Tags', validators=[Regexp(regex=RE_SYSINFO_REGISTRYCHECK_TAGS, message="Invalid input")])
    Path = StringField('Path', validators=[Regexp(regex=RE_SYSINFO_REGISTRYCHECK_PATH, message="Invalid input")])
    Key = StringField('Key', validators=[Regexp(regex=RE_SYSINFO_REGISTRYCHECK_KEY, message="Invalid input")])
    Expected = StringField('Expected', validators=[Regexp(regex=RE_SYSINFO_REGISTRYCHECK_EXPECTED, message="Invalid input")])
    KeyExists = BooleanField('KeyExists')
    ValueMatch = BooleanField('ValueMatch')
    SystemGroup = StringField('SystemGroup', validators=[Regexp(regex=RE_SYSINFO_SYSTEMGROUP, message="Invalid input")])
    CurrentValue = StringField('CurrentValue', validators=[Regexp(regex=RE_SYSINFO_REGISTRYCHECK_CURRENTVALUE, message="Invalid input")])

    Host = StringField('Host', validators=[Regexp(regex=RE_SYSINFO_HOSTNAME, message="Invalid input")])

    InvertName = BooleanField('Invert Name')
    InvertCategory = BooleanField('Invert Category')
    InvertDescription = BooleanField('Invert Description')
    InvertTags = BooleanField('Invert Tags')
    InvertPath = BooleanField('Invert Path')
    InvertKey = BooleanField('Invert Key')
    InvertSystemGroup = BooleanField('Invert SystemGroup')
    InvertExpected = BooleanField('Invert Expected')
    InvertCurrentValue = BooleanField('Invert CurrentValue')
    UseKeyExists = BooleanField('use KeyExists')
    UseValueMatch = BooleanField('use ValueMatch')
    InvertHost = BooleanField('Invert Host')

    search = SubmitField('Search')
    download = SubmitField('Download Excel')


class FileExistCheckSearchForm(FlaskForm):
    Name = StringField('Name', validators=[Regexp(regex=RE_SYSINFO_REGISTRYCHECK_NAME, message="Invalid input")])
    File = StringField('File', validators=[Regexp(regex=RE_SYSINFO_FILENAME, message="Invalid input")])
    FileExist = BooleanField('FileExists')
    HashMatch = BooleanField('HashMatch')

    Host = StringField('Host', validators=[Regexp(regex=RE_SYSINFO_HOSTNAME, message="Invalid input")])

    InvertName = BooleanField('Invert Name')
    InvertFile = BooleanField('Invert Category')
    UseFileExist = BooleanField('use FileExist')
    UseHashMatch = BooleanField('use HashMatch')
    InvertHost = BooleanField('Invert Host')

    search = SubmitField('Search')
    download = SubmitField('Download Excel')
