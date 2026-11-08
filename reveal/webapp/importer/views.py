import os
import uuid

from flask import render_template, flash, current_app
from werkzeug.utils import secure_filename
from flask_login import login_required
from sqlalchemy.exc import SQLAlchemyError

from reveal.webapp.importer import import_bp
from reveal.webapp.importer.forms import UploadFileForm, ImportAllForm
from reveal.core.importer.utils import import_file
from reveal.core.importer.utils import hash_file
from reveal.core.extentions import db
from reveal.core.models.files import UploadedFile


@import_bp.route('/upload/', methods=['GET'])
@login_required
def upload():
    form = UploadFileForm()
    return render_template("importer/upload.html", title="Upload", form=form)


@import_bp.route('/files/uploads/', methods=['POST'])
@login_required
def upload_post():
    form = UploadFileForm()
    if form.validate_on_submit():
        for file in form.Files.data:
            filename = secure_filename(file.filename)
            if filename != '':
                file_ext = os.path.splitext(filename)[1].lower()
                if file_ext not in current_app.config['UPLOAD_EXTENSIONS']:
                    flash('File: {0} -> invalid file type'.format(filename))
                    continue

                try:
                    uid = str(uuid.uuid4())
                    # keep the file extension (XML or JSON). The importer detects the format by the content.
                    fullpath = os.path.join(current_app.config['UPLOAD_DIR'], uid + file_ext)
                    file.save(fullpath)

                    upload_file = UploadedFile()
                    upload_file.OriginalFilename = filename
                    upload_file.Fullpath = fullpath
                    upload_file.UUID = uid
                    upload_file.Hash = hash_file(fullpath)
                    upload_file.Imported = False

                    db.session.add(upload_file)
                    db.session.commit()
                    flash('File: {0} -> uploaded successfully'.format(filename))
                except SQLAlchemyError as e:
                    db.session.rollback()
                    flash('File: {0} -> already uploaded'.format(filename), category='error')
                    #print("Error while uploading file. Error: {0}".format(str(e.__dict__['orig'])))
                    os.remove(fullpath)

    return render_template("importer/upload.html", title="Upload", form=form)


@import_bp.route('/files/uploads/', methods=['GET'])
@login_required
def list_uploaded_files():
    uploaded_files = UploadedFile.query.all()

    form = ImportAllForm()
    return render_template('importer/file_list.html', uploaded_files=uploaded_files, form=form, title="Importable Files")


@import_bp.route("/files/import/<uid>", methods=['GET'])
@login_required
def import_file_by_uid(uid):
    uid_str = str(uuid.UUID(uid))
    uploaded_file = UploadedFile.query.filter(UploadedFile.UUID == uid_str).first()

    if not uploaded_file:
        flash('File with UUID {0} not found'.format(uid_str))
    else:
        if uploaded_file.Imported:
            flash('File: {0} already imported'.format(UploadedFile.OriginalFilename))
        try:
            uploaded_file.Imported = True
            db.session.commit()
            import_file(uploaded_file.Fullpath)
            flash('File: {0} imported successfully'.format(UploadedFile.OriginalFilename))
            os.remove(uploaded_file.Fullpath)
        except SQLAlchemyError as e:
            db.session.rollback()

    uploaded_files = UploadedFile.query.all()

    form = ImportAllForm()
    return render_template('importer/file_list.html', uploaded_files=uploaded_files, form=form, title="Importable Files")


@import_bp.route("/files/delete/<uid>", methods=['GET'])
@login_required
def delete_file_by_uid(uid):
    uid_str = str(uuid.UUID(uid))
    uploaded_file = UploadedFile.query.filter(UploadedFile.UUID == uid_str).first()

    if not uploaded_file:
        flash('File with UUID {0} not found'.format(uid_str))
    else:
        if not uploaded_file.Imported:
            try:
                # read the path before the object is deleted (attributes are expired after commit)
                fullpath = uploaded_file.Fullpath
                db.session.delete(uploaded_file)
                db.session.commit()
                if fullpath and os.path.exists(fullpath):
                    os.remove(fullpath)
            except SQLAlchemyError as e:
                db.session.rollback()
        else:
            flash('File with UUID {0} already imported and can not be deleted'.format(uid_str))
    uploaded_files = UploadedFile.query.all()

    form = ImportAllForm()
    return render_template('importer/file_list.html', uploaded_files=uploaded_files, form=form, title="Importable Files")


@import_bp.route('/files/import/all/', methods=['POST'])
@login_required
def import_all():
    uploaded_files = UploadedFile.query.all()

    form = ImportAllForm()
    if form.validate_on_submit():
        for u in uploaded_files:
            if not u.Imported:
                try:
                    if not u.Imported:
                        u.Imported = True
                        db.session.commit()
                        import_file(u.Fullpath)
                        flash('File: {0} imported successfully'.format(u.UUID))
                        os.remove(u.Fullpath)
                    else:
                        flash('File: {0} already imported'.format(u.UUID))
                except SQLAlchemyError as e:
                    db.session.rollback()
                    flash('Error! File: {0} -> already uploaded'.format(u.UUID), category='error')
                    #print("Error while importing file. Error: {0}".format(str(e.__dict__['orig'])))
    uploaded_files = UploadedFile.query.all()

    return render_template('importer/file_list.html', uploaded_files=uploaded_files, form=form, title="Importable Files")
