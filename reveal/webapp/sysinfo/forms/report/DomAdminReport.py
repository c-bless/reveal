from wtforms import SubmitField, SelectField

from reveal.webapp.sysinfo.forms import RevealReportSearchForm


class DomAdminReportForm(RevealReportSearchForm):
    word = SubmitField('Word')
    brief = SubmitField('Excel Hosts (Brief)')
    full = SubmitField('Excel Hosts (Full)')
    memberships = SubmitField('Excel Memberships')
    TemplateFile = SelectField('Template (Word)')
    word = SubmitField('Word')