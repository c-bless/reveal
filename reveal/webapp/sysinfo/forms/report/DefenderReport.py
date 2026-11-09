from wtforms import SubmitField, SelectField

from reveal.webapp.sysinfo.forms import RevealReportSearchForm


class DefenderReportForm(RevealReportSearchForm):
    """ Reports about Microsoft Defender (system group / location / label filter and exports) """
    brief = SubmitField('Excel (brief)')
    full = SubmitField('Excel (full)')
    excel = SubmitField('Excel (Defender details)')
    TemplateFile = SelectField('Template (Word)')
    word = SubmitField('Word')
