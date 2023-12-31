from flask_wtf import FlaskForm
from wtforms import SubmitField, SelectField

from reveal.webapp.sysinfo.forms import RevealReportSearchForm


class WSHReportForm(RevealReportSearchForm):
    brief = SubmitField('Excel Hosts (brief)')
    full = SubmitField('Excel Hosts (full)')
    TemplateFile = SelectField('Template (Word)')
    word = SubmitField('Word')