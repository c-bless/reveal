from wtforms import SubmitField, SelectField

from reveal.webapp.sysinfo.forms import RevealReportSearchForm


class AutoAdminReportForm(RevealReportSearchForm):
    brief = SubmitField('Excel Hosts (Brief)')
    full = SubmitField('Excel Hosts (Full)')
    TemplateFile = SelectField('Template (Word)')
    word = SubmitField('Word')