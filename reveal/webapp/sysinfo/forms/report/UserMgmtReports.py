from wtforms import StringField, SubmitField, BooleanField, SelectField
from wtforms.validators import Regexp, Optional

from reveal.webapp.sysinfo.forms import RevealReportSearchForm

from reveal.core.regex import RE_SYSINFO_DOMAIN
from reveal.core.regex import RE_SYSINFO_HOSTNAME
from reveal.core.regex import RE_SYSINFO_USER_NAME

class DirectAssignmentReportForm(RevealReportSearchForm):
    excel = SubmitField('Excel')
    #TemplateFile = SelectField('Template (Word)')
    #word = SubmitField('Word')


class HostByLocalUserSearchForm(RevealReportSearchForm):
    Name = StringField('Local User', validators=[Optional(),
                                                 Regexp(regex=RE_SYSINFO_HOSTNAME, message="Invalid input")] )

    excel = SubmitField('Excel (Hosts)')
    #TemplateFile = SelectField('Template (Word)')
    #word = SubmitField('Word')


class LocalAdminSearchForm(RevealReportSearchForm):
    Hostname = StringField('Hostname', validators=[Regexp(regex=RE_SYSINFO_HOSTNAME, message="Invalid input")])
    Domain = StringField('Domain', validators=[Regexp(regex=RE_SYSINFO_DOMAIN, message="Invalid input")])
    Username = StringField('Username', validators=[Regexp(regex=RE_SYSINFO_USER_NAME, message="Invalid input")])

    InvertHostname = BooleanField('Invert Hostname')
    InvertDomain = BooleanField('Invert Domain')
    InvertUsername = BooleanField('Invert Username')

    excel = SubmitField('Download Excel (Full)')
    TemplateFile = SelectField('Template (Word)')
    word = SubmitField('Word')


class LocalGroupMemberSearchForm(RevealReportSearchForm):
    excel = SubmitField('Download Excel (Full)')
    TemplateFile = SelectField('Template (Word)')
    word = SubmitField('Word')