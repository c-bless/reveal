from wtforms import StringField, SubmitField, BooleanField, SelectField
from wtforms.validators import Regexp, Optional, DataRequired


from reveal.webapp.sysinfo.forms import RevealReportSearchForm

from reveal.core.regex import RE_SYSINFO_SERVICE_ACCOUNTNAME
from reveal.core.regex import RE_SYSINFO_SERVICE_PERMISSIONSTRING
from reveal.core.regex import RE_SYSINFO_SERVICE_STARTNAME


class UQSPReportForm(RevealReportSearchForm):

    excel = SubmitField('Excel')
    TemplateFile = SelectField('Template (Word)')
    word = SubmitField('Word')


class ServiceAclSearchForm(RevealReportSearchForm):
    User = StringField('User',
                       validators=[
                            Optional(),
                            Regexp(regex=RE_SYSINFO_SERVICE_ACCOUNTNAME, message="Invalid input") ]
                       )
    Permission = StringField('Permission',
                             validators=[
                            Optional(),
                                 Regexp(regex=RE_SYSINFO_SERVICE_PERMISSIONSTRING, message="Invalid input") ]
                             )
    InvertUser = BooleanField('Invert User')
    InvertPermission = BooleanField('Invert Permission')

    excel = SubmitField('Excel')
    TemplateFile = SelectField('Template (Word)')
    word = SubmitField('Word')



class ServiceUserContextSearchForm(RevealReportSearchForm):
    Startname = StringField('Startname',
                            validators=[
                                DataRequired(message="Data required"),
                                Regexp(regex=RE_SYSINFO_SERVICE_STARTNAME, message="Invalid input") ]
                       )
    InvertStartname = BooleanField('Invert Startname')

    excel = SubmitField('Excel')
    TemplateFile = SelectField('Template (Word)')
    word = SubmitField('Word')


class ModifiableServicesReportForm(RevealReportSearchForm):
    excel = SubmitField('Excel')
    TemplateFile = SelectField('Template (Word)')
    word = SubmitField('Word')