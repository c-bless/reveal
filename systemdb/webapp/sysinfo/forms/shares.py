from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, BooleanField
from wtforms.validators import Regexp

from systemdb.core.regex import RE_SYSINFO_Share_NAME
from systemdb.core.regex import RE_SYSINFO_Share_PATH
from systemdb.core.regex import RE_SYSINFO_Share_DESCRIPTION
from systemdb.core.regex import RE_SYSINFO_HOSTNAME


class ShareSearchForm(FlaskForm):
    Name = StringField('Name', validators=[Regexp(regex=RE_SYSINFO_Share_NAME, message="Invalid input")])

    Path = StringField('Path', validators=[Regexp(regex=RE_SYSINFO_Share_PATH, message="Invalid input")])
    Host = StringField('Host', validators=[Regexp(regex=RE_SYSINFO_HOSTNAME, message="Invalid input")])
    Description = StringField('Description', validators=[Regexp(regex=RE_SYSINFO_Share_DESCRIPTION,
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


