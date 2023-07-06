from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Regexp

class ProductSearchForm(FlaskForm):
    Caption = StringField('Caption', validators=[Regexp(regex="^[a-zA-Z0-9 \.\-\(\)\_]+$", message="Invalid input")])
    Name = StringField('Name', validators=[Regexp(regex="^[a-zA-Z0-9 \.\-\(\)\_]+$", message="Invalid input")])

    Version = StringField('Version', validators=[Regexp(regex="^[a-zA-Z0-9 \.\-\_]+$", message="Invalid input")])
    Host = StringField('Host', validators=[Regexp(regex="^[a-zA-Z0-9 \.\-\_]+$", message="Invalid input")])
    InstallLocation = StringField('Name', validators=[Regexp(regex="^[a-zA-Z0-9 \.\-\:\(\)\_]+$",
                                                             message="Invalid input")])

    InvertCaption = BooleanField('Invert Caption')
    InvertName = BooleanField('Invert Name')
    InvertVersion = BooleanField('Invert Version')
    InvertHost = BooleanField('Invert Host')
    InvertInstallLocation = BooleanField('Invert InstallLocation')

    search = SubmitField('Search')
    download = SubmitField('Download (Excel)')


