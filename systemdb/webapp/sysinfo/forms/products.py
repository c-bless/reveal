from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, BooleanField
from wtforms.validators import Regexp

from systemdb.core.regex import RE_SYSINFO_PRODUCT_CAPTION
from systemdb.core.regex import RE_SYSINFO_PRODUCT_NAME
from systemdb.core.regex import RE_SYSINFO_PRODUCT_HOST
from systemdb.core.regex import RE_SYSINFO_PRODUCT_INSTALLLOCATION
from systemdb.core.regex import RE_SYSINFO_PRODUCT_VERSION

class ProductSearchForm(FlaskForm):
    Caption = StringField('Caption',
                          validators=[Regexp(regex=RE_SYSINFO_PRODUCT_CAPTION, message="Invalid input")])
    Name = StringField('Name',
                       validators=[Regexp(regex=RE_SYSINFO_PRODUCT_NAME, message="Invalid input")])

    Version = StringField('Version',
                          validators=[Regexp(regex=RE_SYSINFO_PRODUCT_VERSION, message="Invalid input")])
    Host = StringField('Host',
                       validators=[Regexp(regex=RE_SYSINFO_PRODUCT_HOST, message="Invalid input")])
    InstallLocation = StringField('InstallLocation',
                                  validators=[
                                      Regexp(regex=RE_SYSINFO_PRODUCT_INSTALLLOCATION,message="Invalid input")]
                                  )

    InvertCaption = BooleanField('Invert Caption')
    InvertName = BooleanField('Invert Name')
    InvertVersion = BooleanField('Invert Version')
    InvertHost = BooleanField('Invert Host')
    InvertInstallLocation = BooleanField('Invert InstallLocation')

    search = SubmitField('Search')
    download = SubmitField('Download (Excel)')


