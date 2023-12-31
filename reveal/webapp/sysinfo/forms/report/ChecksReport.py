from wtforms import SubmitField, SelectField

from reveal.webapp.sysinfo.forms import RevealReportSearchForm


class RegistryCheckReportForm(RevealReportSearchForm):
    TemplateFile = SelectField('Template (Word)')

    excel = SubmitField('Excel')
    word = SubmitField('Word')