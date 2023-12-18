from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, BooleanField
from wtforms.validators import Regexp, Optional

from systemdb.core.regex import RE_SYSINFO_HOSTNAME
from systemdb.core.regex import RE_SYSINFO_DOMAIN
from systemdb.core.regex import RE_SYSINFO_DOMAINROLE
from systemdb.core.regex import RE_SYSINFO_OSVERSION
from systemdb.core.regex import RE_SYSINFO_OSBUILDNUMBER_CHARS
from systemdb.core.regex import RE_SYSINFO_OSNAME
from systemdb.core.regex import RE_SYSINFO_SYSTEMGROUP
from systemdb.core.regex import RE_SYSINFO_LOCATION

class HostSearchForm(FlaskForm):
    Hostname = StringField('Hostname', validators=[Regexp(regex=RE_SYSINFO_HOSTNAME, message="Invalid input")] )
    Domain = StringField('Domain', validators=[Regexp(regex=RE_SYSINFO_DOMAIN, message="Invalid input")] )
    DomainRole = StringField('DomainRole', validators=[Regexp(regex=RE_SYSINFO_DOMAINROLE, message="Invalid input")] )
    OSVersion = StringField('OSVersion', validators=[Regexp(regex=RE_SYSINFO_OSVERSION, message="Invalid input")] )
    OSBuildNumber = StringField('OSBuildNumber', validators=[Regexp(regex=RE_SYSINFO_OSBUILDNUMBER_CHARS, message="Invalid input")] )
    OSName = StringField('OSName', validators=[Regexp(regex=RE_SYSINFO_OSNAME, message="Invalid input")] )
    SystemGroup = StringField('SystemGroup', validators=[Regexp(regex=RE_SYSINFO_SYSTEMGROUP, message="Invalid input")] )
    Location = StringField('Location', validators=[Regexp(regex=RE_SYSINFO_LOCATION, message="Invalid input")] )

    InvertHostname = BooleanField('Invert Hostname')
    InvertDomain = BooleanField('Invert Domain')
    InvertDomainRole = BooleanField('Invert DomainRole')
    InvertOSVersion = BooleanField('Invert OSVersion')
    InvertOSBuildNumber = BooleanField('Invert OSBuildNumber')
    InvertOSName = BooleanField('Invert OSName')
    InvertSystemGroup = BooleanField('Invert SystemGroup')
    InvertLocation = BooleanField('Invert Location')

    search = SubmitField('Search')
    brief = SubmitField('Download Excel (Brief)')
    full = SubmitField('Download Excel (Full)')

