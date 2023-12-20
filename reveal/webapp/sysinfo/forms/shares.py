from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, BooleanField
from wtforms.validators import Regexp

from reveal.core.regex import RE_SYSINFO_SHARE_NAME
from reveal.core.regex import RE_SYSINFO_SHARE_PATH
from reveal.core.regex import RE_SYSINFO_SHARE_DESCRIPTION
from reveal.core.regex import RE_SYSINFO_HOSTNAME


class ShareSearchForm(FlaskForm):
    Name = StringField('Name', validators=[Regexp(regex=RE_SYSINFO_SHARE_NAME, message="Invalid input")])

    Path = StringField('Path', validators=[Regexp(regex=RE_SYSINFO_SHARE_PATH, message="Invalid input")])
    Host = StringField('Host', validators=[Regexp(regex=RE_SYSINFO_HOSTNAME, message="Invalid input")])
    Description = StringField('Description', validators=[Regexp(regex=RE_SYSINFO_SHARE_DESCRIPTION,
                                                                message="Invalid input")])

    InvertName = BooleanField('Invert Name')
    InvertPath = BooleanField('Invert Path')
    InvertDescription = BooleanField('Invert Description')
    InvertHost = BooleanField('Invert Host')

    Hide_ADMIN_Dollar = BooleanField('Hide "Admin$"')
    Hide_IPC_Dollar = BooleanField('Hide "IPC$"')
    Hide_C_Dollar = BooleanField('Hide "C$"')
    Hide_D_Dollar = BooleanField('Hide "D$"')
    Hide_E_Dollar = BooleanField('Hide "E$"')

    search = SubmitField('Search')
    download = SubmitField('Download (Excel)')


