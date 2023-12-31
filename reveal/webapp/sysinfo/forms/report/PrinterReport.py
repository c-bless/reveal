from wtforms import SubmitField

from reveal.webapp.sysinfo.forms import RevealReportSearchForm

class FilePrinterReportForm(RevealReportSearchForm):
    excel = SubmitField('Excel')
    #TemplateFile = SelectField('Template (Word)')
    #word = SubmitField('Word')