from wtforms import SubmitField, IntegerField, SelectField

from reveal.webapp.sysinfo.forms import RevealReportSearchForm


class EOLReportForm(RevealReportSearchForm):
    brief = SubmitField('Excel Hosts (Brief)')
    full = SubmitField('Excel Hosts (Full)')
    #TemplateFile = SelectField('Template (Word)')
    #word = SubmitField('Word')


class LastUpdateReportForm(RevealReportSearchForm):
    Days = IntegerField('Number of days', default= 180)

    brief = SubmitField('Excel Hosts (Brief)')
    full = SubmitField('Excel Hosts (Full)')
    TemplateFile = SelectField('Template (Word)')
    word = SubmitField('Word')