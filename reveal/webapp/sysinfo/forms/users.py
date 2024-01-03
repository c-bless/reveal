from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, BooleanField, IntegerField
from wtforms.validators import Regexp

from reveal.core.regex import RE_SYSINFO_USER_NAME
from reveal.core.regex import RE_SYSINFO_USER_DESCRIPTION
from reveal.core.regex import RE_SID_ALLOWED_CHARS
from reveal.core.regex import RE_SYSINFO_USER_FULLNAME
from reveal.core.regex import RE_SYSINFO_HOSTNAME
from reveal.core.regex import RE_SYSINFO_SYSTEMGROUP


class LocalUserSearchForm(FlaskForm):
    Name = StringField('Name', validators=[Regexp(regex=RE_SYSINFO_USER_NAME, message="Invalid input")])
    AccountType = IntegerField('AccountType',default=512, description="512 = LocalAccount")
    SID = StringField('SID', validators=[Regexp(regex=RE_SID_ALLOWED_CHARS, message="Invalid input")])
    Description = StringField('Description', validators=[Regexp(regex=RE_SYSINFO_USER_DESCRIPTION, message="Invalid input")])
    FullName = StringField('FullName', validators=[Regexp(regex=RE_SYSINFO_USER_FULLNAME, message="Invalid input")])
    Host = StringField('Host',
                       validators=[Regexp(regex=RE_SYSINFO_HOSTNAME, message="Invalid input")])
    SystemGroup = StringField('Systemgroup',
                       validators=[Regexp(regex=RE_SYSINFO_SYSTEMGROUP, message="Invalid input")])

    InvertName = BooleanField('Invert Name')
    InvertAccountType = BooleanField('Invert AccountType')
    InvertSID = BooleanField('Invert SID')
    InvertDescription = BooleanField('Invert Description')
    InvertFullName = BooleanField('Invert FullName')
    InvertHost = BooleanField('Invert Host')
    InvertSystemGroup = BooleanField('Invert Systemgroup')

    Lockout = BooleanField('Lockout')
    UseLockout = BooleanField('use Lockout')

    PasswordChanged = BooleanField('PasswordChanged')
    UsePasswordChanged = BooleanField('use PasswordChanged')

    PasswordRequired = BooleanField('PasswordRequired')
    UsePasswordRequired = BooleanField('use PasswordRequired')

    DescriptionNotEmpty = BooleanField('Description NotEmpty')
    UseDescriptionNotEmpty = BooleanField('use DescriptionNotEmpty')

    search = SubmitField('Search')
    download = SubmitField('Download Excel')
