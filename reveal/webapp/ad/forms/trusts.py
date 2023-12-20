from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, BooleanField
from wtforms.validators import Regexp

from reveal.core.regex import RE_AD_DOMAINNAME
from reveal.core.regex import RE_AD_TRUSTS_SOURCE
from reveal.core.regex import RE_AD_TRUSTS_TARGET
from reveal.core.regex import RE_AD_TRUSTS_DIRECTION
from reveal.core.regex import RE_AD_DISTINGUISHED_NAME


class ADTrustSearchForm(FlaskForm):
    Source = StringField('Source', validators=[Regexp(regex=RE_AD_TRUSTS_SOURCE, message="Invalid input")])
    Target = StringField('Target', validators=[Regexp(regex=RE_AD_TRUSTS_TARGET, message="Invalid input")])

    Direction = StringField('Direction', validators=[Regexp(regex=RE_AD_TRUSTS_DIRECTION, message="Invalid input")])
    Domain = StringField('Domain', validators=[Regexp(regex=RE_AD_DOMAINNAME, message="Invalid input")])
    DistinguishedName = StringField('DistinguishedName',
                                  validators=[
                                      Regexp(regex=RE_AD_DISTINGUISHED_NAME,message="Invalid input")]
                                  )

    InvertSource = BooleanField('Invert Source')
    InvertTarget = BooleanField('Invert Target')
    InvertDirection = BooleanField('Invert Direction')
    InvertDomain = BooleanField('Invert Domain')
    InvertDistinguishedName = BooleanField('Invert DistinguishedName')

    search = SubmitField('Search')
    download = SubmitField('Download (Excel)')


