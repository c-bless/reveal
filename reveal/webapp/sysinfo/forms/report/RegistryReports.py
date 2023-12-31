from wtforms import SubmitField, BooleanField,SelectField

from reveal.webapp.sysinfo.forms import RevealReportSearchForm


class WinlogonReportForm(RevealReportSearchForm):
    Decrypt = BooleanField('Decrypt Password')
    brief = SubmitField('Hosts (brief)')
    full = SubmitField('Hosts (full)')
    winlogon = SubmitField('Winlogon')
    TemplateFile = SelectField('Template (Word)')
    word = SubmitField('Word')