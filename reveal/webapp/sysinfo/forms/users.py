from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, BooleanField, IntegerField, SelectField
from wtforms.validators import Regexp

from reveal.core.regex import RE_SYSINFO_USER_NAME
from reveal.core.regex import RE_SYSINFO_USER_DESCRIPTION
from reveal.core.regex import RE_SID_ALLOWED_CHARS
from reveal.core.regex import RE_SYSINFO_USER_FULLNAME
from reveal.core.regex import RE_SYSINFO_HOSTNAME
from reveal.core.regex import RE_SYSINFO_SYSTEMGROUP
from reveal.webapp.sysinfo.forms.defender import TRISTATE_CHOICES


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

    # "" = any, "true" = yes, "false" = no
    Lockout = SelectField('Lockout', choices=TRISTATE_CHOICES, default="")
    PasswordChangeable = SelectField('PasswordChangeable', choices=TRISTATE_CHOICES, default="")
    PasswordRequired = SelectField('PasswordRequired', choices=TRISTATE_CHOICES, default="")
    PasswordExpires = SelectField('PasswordExpires', choices=TRISTATE_CHOICES, default="")

    DescriptionNotEmpty = SelectField('Description not empty', choices=TRISTATE_CHOICES, default="")

    search = SubmitField('Search')
    download = SubmitField('Download Excel')
