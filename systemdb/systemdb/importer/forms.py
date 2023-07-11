from flask_wtf import FlaskForm
from wtforms import SubmitField, MultipleFileField, HiddenField
from wtforms.validators import DataRequired, Regexp


class UploadFileForm(FlaskForm):
    Files = MultipleFileField('File(s)', render_kw={'multiple': True})

    Submit = SubmitField('Submit')


class ImportFileForm(FlaskForm):
    File = HiddenField('File')
    Submit = SubmitField('Import')



class ImportAllForm(FlaskForm):
    Submit = SubmitField('Import All')