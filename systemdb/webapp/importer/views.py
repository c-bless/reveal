import os
import uuid

from flask import render_template, flash, current_app
from werkzeug.utils import secure_filename
from flask_login import login_required
from sqlalchemy.exc import SQLAlchemyError

from systemdb.webapp.importer import import_bp
from systemdb.webapp.importer.forms import UploadFileForm, ImportAllForm
from systemdb.core.importer.utils import import_file_once
from systemdb.core.importer.utils import hash_file
from systemdb.core.extentions import db
from systemdb.core.models.files import UploadedFile
from systemdb.core.models.files import ImportedFile


@import_bp.route('/upload/', methods=['GET'])
@login_required
def upload():
    form = UploadFileForm()
    return render_template("upload.html", title="Upload", form=form)


@import_bp.route('/files/uploads/', methods=['POST'])
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

                try:
                    uid = str(uuid.uuid4())
                    fullpath = os.path.join(current_app.config['UPLOAD_DIR'], uid + ".xml")
                    file.save(fullpath)

                    upload_file = UploadedFile()
                    upload_file.OriginalFilename = filename
                    upload_file.Fullpath = fullpath
                    upload_file.UUID = uid

                    filehash = hash_file(fullpath)

                    if ImportedFile.is_imported(filehash):
                        upload_file.Imported = True

                    print(3)
                    db.session.add(upload_file)
                    db.session.commit()

                    print(4)

                    flash('File: {0} -> uploaded successfully'.format(filename))
                except SQLAlchemyError as e:
                    db.session.rollback()
                    print("Error while creating Hotfixes. Error: {0}".format(str(e.__dict__['orig'])))
                    os.remove(fullpath)

    return render_template("upload.html", title="Upload", form=form)


@import_bp.route('/files/uploads/', methods=['GET'])
@login_required
def list_uploaded_files():
    uploaded_files = UploadedFile.query.all()

    form = ImportAllForm()
    return render_template('file_list.html', uploaded_files=uploaded_files, form=form, title="Importable Files")


@import_bp.route("/files/import/<uid>", methods=['GET'])
@login_required
def import_file_by_uid(uid):
    uid_str = str(uuid.UUID(uid))
    uploaded_file = UploadedFile.query.filter(UploadedFile.UUID == uid_str).first()

    if not uploaded_file:
        flash('File with UUID {0} not found'.format(uid_str))
    else:
        fullpath = os.path.join(current_app.config['UPLOAD_DIR'], uid_str + ".xml")

        if import_file_once(fullpath):
            uploaded_file.Imported = True
            db.session.commit()
            flash('File: {0} imported successfully'.format(UploadedFile.OriginalFilename))
        else:
            flash('File: {0} already imported'.format(UploadedFile.OriginalFilename))

    uploaded_files = UploadedFile.query.all()

    form = ImportAllForm()
    return render_template('file_list.html', uploaded_files=uploaded_files, form=form, title="Importable Files")


@import_bp.route("/files/delete/<uid>", methods=['GET'])
@login_required
def delete_file_by_uid(uid):
    uid_str = str(uuid.UUID(uid))
    uploaded_file = UploadedFile.query.filter(UploadedFile.UUID == uid_str).first()

    if not uploaded_file:
        flash('File with UUID {0} not found'.format(uid_str))
    else:
        fullpath = os.path.join(current_app.config['UPLOAD_DIR'], uid_str + ".xml")
        os.remove(fullpath)

    uploaded_files = UploadedFile.query.all()

    form = ImportAllForm()
    return render_template('file_list.html', uploaded_files=uploaded_files, form=form, title="Importable Files")


@import_bp.route('/files/import/all/', methods=['POST'])
@login_required
def import_all():
    uploaded_files = os.listdir(current_app.config['UPLOAD_DIR'])

    form = ImportAllForm()
    if form.validate_on_submit():
        for u in uploaded_files:
            filename = secure_filename(u)
            file_ext = os.path.splitext(filename)[1]
            fullpath = current_app.config['UPLOAD_DIR'] + filename
            print('importing {0}'.format(fullpath))

            if file_ext.endswith(".xml"):
                if import_file_once(fullpath):
                    flash('File: {0} imported successfully'.format(filename))
                    os.remove(fullpath)
                else:
                    flash('File: {0} already imported'.format(filename))

    uploaded_files = os.listdir(current_app.config['UPLOAD_DIR'])

    return render_template('file_list.html', uploaded_files=uploaded_files, form=form, title="Importable Files")
