from wtforms import SubmitField, SelectField

from reveal.webapp.sysinfo.forms import RevealReportSearchForm


class WSUSReportForm(RevealReportSearchForm):
    TemplateFile = SelectField('Template (Word)')

    word = SubmitField('Word')

    brief = SubmitField('Excel Hosts (brief)')
    full = SubmitField('Excel Hosts (full)')
    wsus = SubmitField('Excel WSUS')