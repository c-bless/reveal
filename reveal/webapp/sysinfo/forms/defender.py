from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, BooleanField, SelectField
from wtforms.validators import Regexp, Optional

from reveal.core.regex import RE_SYSINFO_HOSTNAME
from reveal.core.regex import RE_SYSINFO_DOMAIN
from reveal.core.regex import RE_SYSINFO_OSNAME
from reveal.core.regex import RE_SYSINFO_SYSTEMGROUP
from reveal.core.regex import RE_SYSINFO_LOCATION
from reveal.core.regex import RE_SYSINFO_LABEL
from reveal.core.regex import RE_SYSINFO_DEFENDER_EXCLUSION


TRISTATE_CHOICES = [("", "Any"), ("true", "Yes"), ("false", "No")]


class DefenderSearchForm(FlaskForm):
    Hostname = StringField('Hostname', validators=[Regexp(regex=RE_SYSINFO_HOSTNAME, message="Invalid input")])
    Domain = StringField('Domain', validators=[Regexp(regex=RE_SYSINFO_DOMAIN, message="Invalid input")])
    OSName = StringField('OSName', validators=[Regexp(regex=RE_SYSINFO_OSNAME, message="Invalid input")])
    SystemGroup = StringField('SystemGroup', validators=[Regexp(regex=RE_SYSINFO_SYSTEMGROUP, message="Invalid input")])
    Location = StringField('Location', validators=[Regexp(regex=RE_SYSINFO_LOCATION, message="Invalid input")])
    Label = StringField('Label', validators=[Regexp(regex=RE_SYSINFO_LABEL, message="Invalid input")])

    InvertHostname = BooleanField('Invert Hostname')
    InvertDomain = BooleanField('Invert Domain')
    InvertOSName = BooleanField('Invert OSName')
    InvertSystemGroup = BooleanField('Invert SystemGroup')
    InvertLocation = BooleanField('Invert Location')
    InvertLabel = BooleanField('Invert Label')

    # Defender status (Get-MpComputerStatus): "" = any, "true" = enabled, "false" = disabled
    RealTimeProtectionEnabled = SelectField('Real-time protection', choices=TRISTATE_CHOICES, default="")
    AntivirusEnabled = SelectField('Antivirus', choices=TRISTATE_CHOICES, default="")
    AMServiceEnabled = SelectField('Defender service', choices=TRISTATE_CHOICES, default="")
    BehaviorMonitorEnabled = SelectField('Behavior monitoring', choices=TRISTATE_CHOICES, default="")
    IoavProtectionEnabled = SelectField('Download scanning (IOAV)', choices=TRISTATE_CHOICES, default="")
    OnAccessProtectionEnabled = SelectField('On-access protection', choices=TRISTATE_CHOICES, default="")
    NISEnabled = SelectField('Network inspection (NIS)', choices=TRISTATE_CHOICES, default="")
    AnyProtectionDisabled = BooleanField('At least one protection component disabled')

    # Defender exclusions (Get-MpPreference)
    HasExclusions = SelectField('Exclusions configured', default="", choices=[
        ("", "Any"), ("yes", "Yes"), ("no", "No"), ("not_readable", "Not readable (collector without admin rights)")])
    ExclusionContains = StringField('Exclusion contains', validators=[
        Optional(), Regexp(regex=RE_SYSINFO_DEFENDER_EXCLUSION, message="Invalid input")])

    search = SubmitField('Search')
    full = SubmitField('Download Excel (Hosts)')
    defender = SubmitField('Download Excel (Defender Overview)')
