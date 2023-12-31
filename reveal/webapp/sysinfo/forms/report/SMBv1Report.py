from wtforms import SubmitField, SelectField

from reveal.webapp.sysinfo.forms import RevealReportSearchForm


class SMBv1ReportForm(RevealReportSearchForm):

    brief = SubmitField('Excel (brief)')
    full = SubmitField('Excel (full)')
    TemplateFile = SelectField('Template (Word)')
    word = SubmitField('Word')