from flask import render_template, abort, Response, redirect, url_for

from . import ad_bp

from ..core.ad_models import ADComputer, ADUser
from .export_func import generate_computer_excel, generate_user_excel


@ad_bp.route('/ad/computer/export/excel/', methods=['GET'])
def export_computer_excel():
    computer_list = ADComputer.query.all()

    output = generate_computer_excel(computer_list=computer_list)

    return Response(output, mimetype="text/xlsx",
                    headers={"Content-disposition": "attachment; filename=ad-computer.xlsx",
                             "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" })

    return redirect(url_for('ad.computer_list'))

@ad_bp.route('/ad/users/export/excel/', methods=['GET'])
def export_user_excel():
    user_list = ADUser.query.all()

    output = generate_user_excel(user_list=user_list)

    return Response(output, mimetype="text/xlsx",
                    headers={"Content-disposition": "attachment; filename=ad-user.xlsx",
                             "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" })

    return redirect(url_for('ad.user_list'))