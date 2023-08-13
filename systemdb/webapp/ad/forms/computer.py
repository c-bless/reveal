from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, BooleanField, IntegerField
from wtforms.validators import Regexp
from wtforms.validators import Optional
from wtforms.validators import IPAddress
from wtforms.validators import NumberRange


from systemdb.core.regex import RE_AD_HOSTNAME
from systemdb.core.regex import RE_AD_OS
from systemdb.core.regex import RE_AD_SPN
from systemdb.core.regex import RE_AD_DOMAINNAME
from systemdb.core.regex import RE_AD_SAMACCOUNT
from systemdb.core.regex import RE_AD_DISTINGUISHED_NAME
from systemdb.core.regex import RE_SID_USER_ACCOUNTS


class ADComputerSearchForm(FlaskForm):
    DNSHostName = StringField('DNSHostName', validators=[Regexp(regex=RE_AD_HOSTNAME, message="Invalid input")])
    SamAccountName = StringField('SamAccountName', validators=[Regexp(regex=RE_AD_SAMACCOUNT, message="Invalid input")])
    OperatingSystem = StringField('OperatingSystem', validators=[Regexp(regex=RE_AD_OS, message="Invalid input"), Optional()])
    SID = StringField('SID', validators=[Regexp(regex=RE_SID_USER_ACCOUNTS, message="Invalid input"), Optional()])

    IPv4Address = StringField('IPv4Address', validators=[IPAddress(), Optional()])
    IPv6Address = StringField('IPv6Address', validators=[IPAddress(), Optional()])

    Domain = StringField('Domain', validators=[Regexp(regex=RE_AD_DOMAINNAME, message="Invalid input")])
    DistinguishedName = StringField('DistinguishedName',
                                  validators=[
                                      Regexp(regex=RE_AD_DISTINGUISHED_NAME,message="Invalid input")]
                                  )
    
    Enabled = BooleanField('Enabled Account')
    Disabled = BooleanField('Disabled Account')

    InvertDNSHostName = BooleanField('Invert DNSHostName')
    InvertSID = BooleanField('Invert SID')
    InvertSamAccountName = BooleanField('Invert SamAccountName')
    InvertOperatingSystem = BooleanField('Invert OperatingSystem')
    InvertIPv4Address = BooleanField('Invert IPv4Address')
    InvertIPv6Address = BooleanField('Invert IPv6Address')
    InvertDomain = BooleanField('Invert Domain')
    InvertDistinguishedName = BooleanField('Invert DistinguishedName')

    search = SubmitField('Search')
    download = SubmitField('Download (Excel)')


class DCSearchForm(FlaskForm):
    Hostname = StringField('Hostname', validators=[Regexp(regex=RE_AD_SAMACCOUNT, message="Invalid input")])
    OperatingSystem = StringField('OperatingSystem', validators=[Regexp(regex=RE_AD_OS, message="Invalid input"), Optional()])

    IPv4Address = StringField('IPv4Address', validators=[IPAddress(), Optional()])
    IPv6Address = StringField('IPv6Address', validators=[IPAddress(), Optional()])

    Domain = StringField('Domain', validators=[Regexp(regex=RE_AD_DOMAINNAME, message="Invalid input")])
    DistinguishedName = StringField('DistinguishedName',
                                  validators=[
                                      Regexp(regex=RE_AD_DISTINGUISHED_NAME,message="Invalid input")]
                                  )

    Enabled = BooleanField('Enabled Account')
    Disabled = BooleanField('Disabled Account')

    GlobalCatalog_True = BooleanField('Globale Catalog (True)')
    GlobalCatalog_False = BooleanField('Globale Catalog (False)')

    IsReadOnly_True = BooleanField('IsReadOnly (True)')
    IsReadOnly_False = BooleanField('IsReadOnly (False)')

    LDAP_port = IntegerField('LDAP port', validators=[NumberRange(1,65536), Optional()])
    SSL_port = IntegerField('SSL port', validators=[NumberRange(1,65536), Optional()])

    InvertHostname = BooleanField('Invert Hostname')
    InvertOperatingSystem = BooleanField('Invert OperatingSystem')
    InvertIPv4Address = BooleanField('Invert IPv4Address')
    InvertIPv6Address = BooleanField('Invert IPv6Address')
    InvertDomain = BooleanField('Invert Domain')
    InvertDistinguishedName = BooleanField('Invert DistinguishedName')
    InvertLDAP_port = BooleanField('Invert LDAP port')
    InvertSSL_port = BooleanField('Invert SSL port')

    search = SubmitField('Search')

    download = SubmitField('Download (Excel)')


class ADComputerBySPNSearchForm(FlaskForm):
    SPN = StringField('SPN', validators=[Regexp(regex=RE_AD_SPN, message="Invalid input")])
    Domain = StringField('Domain', validators=[Regexp(regex=RE_AD_DOMAINNAME, message="Invalid input")])

    Enabled = BooleanField('Enabled Account')
    Disabled = BooleanField('Disabled Account')

    InvertSPN = BooleanField('Invert SPN')
    InvertDomain = BooleanField('Invert Domain')

    LDAP = BooleanField('LDAP enabled')
    NOT_LDAP = BooleanField('Not LDAP')

    HOST = BooleanField('HOST enabled')
    NOT_HOST = BooleanField('Not HOST')

    search = SubmitField('Search')
    download = SubmitField('Download (Excel)')


class ADComputerByUnconstraintDelegation(FlaskForm):
    download = SubmitField('Download (Excel)')

