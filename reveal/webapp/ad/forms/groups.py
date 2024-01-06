from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, BooleanField
from wtforms.validators import Regexp
from wtforms.validators import Optional

from reveal.core.regex import RE_AD_DOMAINNAME
from reveal.core.regex import RE_SID_USER_ACCOUNTS
from reveal.core.regex import RE_AD_GROUP_CATEGORY
from reveal.core.regex import RE_AD_GROUP_SCOPE
from reveal.core.regex import RE_AD_GROUP_CN
from reveal.core.regex import RE_AD_SAMACCOUNT


class ADGroupSearchForm(FlaskForm):
    SAMAccountName = StringField('SAMAccountName', validators=[Regexp(regex=RE_AD_SAMACCOUNT, message="Invalid input")])
    SID = StringField('SID', validators=[Regexp(regex=RE_SID_USER_ACCOUNTS, message="Invalid input"), Optional()])

    GroupCategory = StringField('GroupCategory', validators=[Regexp(regex=RE_AD_GROUP_CATEGORY, message="Invalid input")])
    GroupScope = StringField('GroupScope', validators=[Regexp(regex=RE_AD_GROUP_SCOPE, message="Invalid input")])

    Domain = StringField('Domain', validators=[Regexp(regex=RE_AD_DOMAINNAME, message="Invalid input")])
    CN = StringField('CN',validators=[Regexp(regex=RE_AD_GROUP_CN,message="Invalid input")])

    InvertSAMAccountName = BooleanField('Invert SAMAccountName')
    InvertSID = BooleanField('Invert SID')
    InvertGroupCategory = BooleanField('Invert GroupCategory')
    InvertGroupScope = BooleanField('Invert GroupScope')
    InvertCN = BooleanField('Invert CN')
    InvertDomain = BooleanField('Invert Domain')

    search = SubmitField('Search')
    download = SubmitField('Download (Excel)')


class GroupDownload(FlaskForm):
    download = SubmitField('Download Groups')

