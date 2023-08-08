from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, BooleanField
from wtforms.validators import Regexp
from wtforms.validators import Optional

from systemdb.core.regex import RE_AD_DOMAINNAME
from systemdb.core.regex import RE_SID_USER_ACCOUNTS
from systemdb.core.regex import RE_AD_USER_GIVENNAME
from systemdb.core.regex import RE_AD_USER_SURNAME
from systemdb.core.regex import RE_AD_USER_NAME
from systemdb.core.regex import RE_AD_SAMACCOUNT
from systemdb.core.regex import RE_AD_DISTINGUISHED_NAME
from systemdb.core.regex import RE_AD_USER_DISPLAYNAME


class ADUserSearchForm(FlaskForm):
    SAMAccountName = StringField('SAMAccountName', validators=[Regexp(regex=RE_AD_SAMACCOUNT, message="Invalid input")])
    SID = StringField('SID', validators=[Regexp(regex=RE_SID_USER_ACCOUNTS, message="Invalid input"), Optional()])

    GivenName = StringField('GivenName', validators=[Regexp(regex=RE_AD_USER_GIVENNAME, message="Invalid input")])
    Surname = StringField('Surname', validators=[Regexp(regex=RE_AD_USER_SURNAME, message="Invalid input")])
    Name = StringField('Name', validators=[Regexp(regex=RE_AD_USER_NAME, message="Invalid input")])
    DisplayName = StringField('Displayname', validators=[Regexp(regex=RE_AD_USER_DISPLAYNAME, message="Invalid input")])

    Domain = StringField('Domain', validators=[Regexp(regex=RE_AD_DOMAINNAME, message="Invalid input")])
    DistinguishedName = StringField('DistinguishedName',
                                  validators=[
                                      Regexp(regex=RE_AD_DISTINGUISHED_NAME,message="Invalid input")]
                                  )

    Enabled = BooleanField('Enabled Account')
    Disabled = BooleanField('Disabled Account')

    LockedOut_True = BooleanField('LockedOut (True)')
    LockedOut_False = BooleanField('LockedOut (False)')

    InvertSAMAccountName = BooleanField('Invert SAMAccountName')
    InvertSID = BooleanField('Invert SID')
    InvertGivenName = BooleanField('Invert GivenName')
    InvertSurname = BooleanField('Invert Surname')
    InvertName = BooleanField('Invert Name')
    InvertDisplayName = BooleanField('Invert Displayname')
    InvertDomain = BooleanField('Invert Domain')
    InvertDistinguishedName = BooleanField('Invert DistinguishedName')

    search = SubmitField('Search')
    download = SubmitField('Download (Excel)')


