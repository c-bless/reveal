from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Regexp

class ServiceAclSearchForm(FlaskForm):
    User = StringField('User', validators=[DataRequired(message="Data required"),
                                           Regexp(regex="^([a-zA-Z0-9 \.\-\_]+)?$", message="Invalid input") ]
                       )
    Permission = StringField('Permission', validators=[DataRequired(message="Data required"),
                                           Regexp(regex="^([a-zA-Z0-9 \.\-\_]+)?$", message="Invalid input") ]
                             )
    InvertUser = BooleanField('Invert User')
    InvertPermission = BooleanField('Invert Permission')
    search = SubmitField('Search')


class ServiceUserContextSearchForm(FlaskForm):
    Startname = StringField('Startname', validators=[DataRequired(message="Data required"),
                                           Regexp(regex="^([a-zA-Z0-9 \.\-\_]+)?$", message="Invalid input") ]
                       )
    Invert = BooleanField('Invert Startname')
    search = SubmitField('Search')



class ServiceSearchForm(FlaskForm):
    Name = StringField('Name', validators=[Regexp(regex="^([a-zA-Z0-9 \.\-\_]+)?$", message="Invalid input")])
    DisplayName = StringField('DisplayName',
                              validators=[Regexp(regex="^([a-zA-Z0-9 \.\-\_]+)?$", message="Invalid input")])
    SystemName = StringField('Systemname',
                             validators=[Regexp(regex="^([a-zA-Z0-9 \.\-\_]+)?$", message="Invalid input")])
    PathName = StringField('PathName',
                           validators=[Regexp(regex='^([a-zA-Z0-9 \\\.\-\:\(\)\_]+)?$', message="Invalid input")])
    Started = StringField('Started', validators=[Regexp(regex="^([a-zA-Z]+)?$", message="Invalid input")])
    StartMode = StringField('StartMode', validators=[Regexp(regex="^([a-zA-Z0-9 \.\-\_]+)?$", message="Invalid input")])
    StartName = StringField('StartName', validators=[Regexp(regex="^([a-zA-Z0-9 \.\-\_]+)?$", message="Invalid input")])

    InvertName = BooleanField('Invert Name')
    InvertDisplayName = BooleanField('Invert DisplayName')
    InvertSystemName = BooleanField('Invert SystemName')
    InvertPathName = BooleanField('Invert PathName')
    InvertStartMode = BooleanField('Invert StartMode')
    InvertStartName = BooleanField('Invert StartName')
    search = SubmitField('Search')
    download = SubmitField('Download Excel')


