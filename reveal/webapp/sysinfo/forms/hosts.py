from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, BooleanField
from wtforms.validators import Regexp, Optional

from reveal.core.regex import RE_SYSINFO_HOSTNAME
from reveal.core.regex import RE_SYSINFO_DOMAIN
from reveal.core.regex import RE_SYSINFO_DOMAINROLE
from reveal.core.regex import RE_SYSINFO_OSVERSION
from reveal.core.regex import RE_SYSINFO_OSBUILDNUMBER_CHARS
from reveal.core.regex import RE_SYSINFO_OSNAME
from reveal.core.regex import RE_SYSINFO_SYSTEMGROUP
from reveal.core.regex import RE_SYSINFO_LOCATION
from reveal.core.regex import RE_SYSINFO_LABEL

class HostSearchForm(FlaskForm):
    Hostname = StringField('Hostname', validators=[Regexp(regex=RE_SYSINFO_HOSTNAME, message="Invalid input")] )
    Domain = StringField('Domain', validators=[Regexp(regex=RE_SYSINFO_DOMAIN, message="Invalid input")] )
    DomainRole = StringField('DomainRole', validators=[Regexp(regex=RE_SYSINFO_DOMAINROLE, message="Invalid input")] )
    OSVersion = StringField('OSVersion', validators=[Regexp(regex=RE_SYSINFO_OSVERSION, message="Invalid input")] )
    OSBuildNumber = StringField('OSBuildNumber', validators=[Regexp(regex=RE_SYSINFO_OSBUILDNUMBER_CHARS, message="Invalid input")] )
    OSName = StringField('OSName', validators=[Regexp(regex=RE_SYSINFO_OSNAME, message="Invalid input")] )
    SystemGroup = StringField('SystemGroup', validators=[Regexp(regex=RE_SYSINFO_SYSTEMGROUP, message="Invalid input")] )
    Location = StringField('Location', validators=[Regexp(regex=RE_SYSINFO_LOCATION, message="Invalid input")] )
    Label = StringField('Label', validators=[Regexp(regex=RE_SYSINFO_LABEL, message="Invalid input")])

    InvertHostname = BooleanField('Invert Hostname')
    InvertDomain = BooleanField('Invert Domain')
    InvertDomainRole = BooleanField('Invert DomainRole')
    InvertOSVersion = BooleanField('Invert OSVersion')
    InvertOSBuildNumber = BooleanField('Invert OSBuildNumber')
    InvertOSName = BooleanField('Invert OSName')
    InvertSystemGroup = BooleanField('Invert SystemGroup')
    InvertLocation = BooleanField('Invert Location')
    InvertLabel = BooleanField('Invert Label')

    search = SubmitField('Search')
    brief = SubmitField('Download Excel (Brief)')
    full = SubmitField('Download Excel (Full)')

