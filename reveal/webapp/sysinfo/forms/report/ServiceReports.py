from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, BooleanField, SelectField
from wtforms.validators import Regexp, Optional, DataRequired

from reveal.core.regex import RE_SYSINFO_SYSTEMGROUP
from reveal.core.regex import RE_SYSINFO_LOCATION
from reveal.core.regex import RE_SYSINFO_SERVICE_ACCOUNTNAME
from reveal.core.regex import RE_SYSINFO_SERVICE_PERMISSIONSTRING
from reveal.core.regex import RE_SYSINFO_SERVICE_STARTNAME


class UQSPReportForm(FlaskForm):
    SystemGroup = StringField('SystemGroup', validators=[Regexp(regex=RE_SYSINFO_SYSTEMGROUP, message="Invalid input")] )
    Location = StringField('Location', validators=[Regexp(regex=RE_SYSINFO_LOCATION, message="Invalid input")] )

    InvertSystemGroup = BooleanField('Invert SystemGroup')
    InvertLocation = BooleanField('Invert Location')

    search = SubmitField('Search')

    excel = SubmitField('Excel')
    TemplateFile = SelectField('Template (Word)')
    word = SubmitField('Word')


class ServiceAclSearchForm(FlaskForm):
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

    SystemGroup = StringField('SystemGroup', validators=[Regexp(regex=RE_SYSINFO_SYSTEMGROUP, message="Invalid input")])
    Location = StringField('Location', validators=[Regexp(regex=RE_SYSINFO_LOCATION, message="Invalid input")])

    InvertSystemGroup = BooleanField('Invert SystemGroup')
    InvertLocation = BooleanField('Invert Location')

    search = SubmitField('Search')
    excel = SubmitField('Excel')
    TemplateFile = SelectField('Template (Word)')
    word = SubmitField('Word')



class ServiceUserContextSearchForm(FlaskForm):
    Startname = StringField('Startname',
                            validators=[
                                DataRequired(message="Data required"),
                                Regexp(regex=RE_SYSINFO_SERVICE_STARTNAME, message="Invalid input") ]
                       )
    InvertStartname = BooleanField('Invert Startname')
    SystemGroup = StringField('SystemGroup', validators=[Regexp(regex=RE_SYSINFO_SYSTEMGROUP, message="Invalid input")])
    Location = StringField('Location', validators=[Regexp(regex=RE_SYSINFO_LOCATION, message="Invalid input")])

    InvertSystemGroup = BooleanField('Invert SystemGroup')
    InvertLocation = BooleanField('Invert Location')


    search = SubmitField('Search')
    excel = SubmitField('Excel')
    TemplateFile = SelectField('Template (Word)')
    word = SubmitField('Word')


class ModifiableServicesReportForm(FlaskForm):
    SystemGroup = StringField('SystemGroup', validators=[Regexp(regex=RE_SYSINFO_SYSTEMGROUP, message="Invalid input")] )
    Location = StringField('Location', validators=[Regexp(regex=RE_SYSINFO_LOCATION, message="Invalid input")] )

    InvertSystemGroup = BooleanField('Invert SystemGroup')
    InvertLocation = BooleanField('Invert Location')

    search = SubmitField('Search')

    excel = SubmitField('Excel')
    TemplateFile = SelectField('Template (Word)')
    word = SubmitField('Word')