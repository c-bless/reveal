import os

from flask import render_template, flash, current_app
from werkzeug.utils import secure_filename
from flask_login import login_required

from systemdb.webapp.importer import import_bp
from systemdb.webapp.importer.forms import UploadFileForm, ImportAllForm
from systemdb.webapp.importer.utils import import_file_once


@import_bp.route('/upload/', methods=['GET'])
@login_required
def upload():
    form = UploadFileForm()
    return render_template("upload.html", title="Upload", form=form)


@import_bp.route('/upload/', methods=['POST'])
@login_required
def upload_post():
    form = UploadFileForm()
    if form.validate_on_submit():
        for file in form.Files.data:
            filename = secure_filename(file.filename)
            if filename != '':
                file_ext = os.path.splitext(filename)[1]
                if file_ext not in current_app.config['UPLOAD_EXTENSIONS']:
                    flash('File: {0} -> invalid file type'.format(filename))
                    continue

                fullpath = os.path.join(current_app.config['UPLOAD_DIR'], filename)
                file.save(fullpath)
                flash('File: {0} -> uploaded successfully'.format(filename))

    return render_template("upload.html", title="Upload", form=form)


@import_bp.route('/list-uploaded/', methods=['GET'])
@login_required
def list_uploaded_files():
    uploaded_files = os.listdir(current_app.config['UPLOAD_DIR'])

    form = ImportAllForm()
    return render_template('file_list.html', uploaded_files=uploaded_files, form=form, title="Importable Files")


@import_bp.route("/import-file/<file>", methods=['GET'])
@login_required
def import_file_by_name(file):
    uploaded_files = os.listdir(current_app.config['UPLOAD_DIR'])
    filename = secure_filename(file)
    file_ext = os.path.splitext(filename)[1]
    fullpath = current_app.config['UPLOAD_DIR'] + filename

    if file_ext.endswith(".xml") and filename in uploaded_files:
        if import_file_once(fullpath):
            flash('File: {0} uploaded successfully'.format(filename))
        else:
            flash('File: {0} already imported'.format(filename))

    uploaded_files = os.listdir(current_app.config['UPLOAD_DIR'])

    form = ImportAllForm()
    return render_template('file_list.html', uploaded_files=uploaded_files, form=form, title="Importable Files")


@import_bp.route('/import/all/', methods=['POST'])
@login_required
def import_all():
    uploaded_files = os.listdir(current_app.config['UPLOAD_DIR'])

    form = ImportAllForm()
    if form.validate_on_submit():
        for u in uploaded_files:
            filename = secure_filename(u)
            file_ext = os.path.splitext(filename)[1]
            fullpath = current_app.config['UPLOAD_DIR'] + filename

            if file_ext.endswith(".xml"):
                import_file_once(fullpath)
                os.remove(fullpath)

    uploaded_files = os.listdir(current_app.config['UPLOAD_DIR'])

    return render_template('file_list.html', uploaded_files=uploaded_files, form=form, title="Importable Files")
