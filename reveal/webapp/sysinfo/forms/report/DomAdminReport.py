from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, BooleanField, SelectField
from wtforms.validators import Regexp, Optional

from reveal.core.regex import RE_SYSINFO_SYSTEMGROUP
from reveal.core.regex import RE_SYSINFO_LOCATION
from reveal.core.regex import RE_SYSINFO_LABEL


class DomAdminReportForm(FlaskForm):
    SystemGroup = StringField('SystemGroup', validators=[Regexp(regex=RE_SYSINFO_SYSTEMGROUP, message="Invalid input")] )
    Location = StringField('Location', validators=[Regexp(regex=RE_SYSINFO_LOCATION, message="Invalid input")] )
    Label = StringField('Label', validators=[Regexp(regex=RE_SYSINFO_LABEL, message="Invalid input")])

    InvertSystemGroup = BooleanField('Invert SystemGroup')
    InvertLocation = BooleanField('Invert Location')
    InvertLabel = BooleanField('Invert Label')

    search = SubmitField('Search')
    word = SubmitField('Word')
    brief = SubmitField('Excel Hosts (Brief)')
    full = SubmitField('Excel Hosts (Full)')
    memberships = SubmitField('Excel Memberships')
    TemplateFile = SelectField('Template (Word)')
    word = SubmitField('Word')