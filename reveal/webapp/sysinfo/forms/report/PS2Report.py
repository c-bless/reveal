from wtforms import SubmitField, SelectField

from reveal.webapp.sysinfo.forms import RevealReportSearchForm


class PS2ReportForm(RevealReportSearchForm):

    word = SubmitField('Word')
    excel = SubmitField('Excel')
    TemplateFile = SelectField('Template (Word)')
    word = SubmitField('Word')