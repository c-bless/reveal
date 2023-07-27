from flask import render_template, request, Response
from flask_login import login_required

from systemdb.webapp.sysinfo import sysinfo_bp

from systemdb.core.models.sysinfo import ConfigCheck
from systemdb.core.models.sysinfo import Service
from systemdb.webapp.sysinfo.forms.checks import ConfigCheckSearchForm
from systemdb.webapp.sysinfo.export_func import generate_services_excel


@sysinfo_bp.route('/checks/config', methods=['GET', 'POST'])
@login_required
def configcheck_search_list():
    form = ConfigCheckSearchForm()

    if request.method == 'POST':
        filters = []
        if form.validate_on_submit():
            name = form.Name.data
            component = form.Component.data
            method = form.Method.data
            key = form.Key.data
            value = form.Value.data
            result = form.Result.data
            message = form.Message.data
            invertName = form.InvertName.data
            invertComponent = form.InvertComponent.data
            invertMethod = form.InvertMethod.data
            invertKey = form.InvertKey.data
            invertValue = form.InvertValue.data
            invertResult = form.InvertResult.data
            invertMessage = form.InvertMessage.data


            if len(name) > 0:
                if invertName == False:
                    filters.append(ConfigCheck.Name.ilike("%" + name + "%"))
                else:
                    filters.append(ConfigCheck.Name.notilike("%" + name + "%"))
            if len(component) > 0:
                if invertComponent == False:
                    filters.append(ConfigCheck.Component.ilike("%" + component + "%"))
                else:
                    filters.append(ConfigCheck.Component.notilike("%" + component + "%"))
            if len(method) > 0:
                if invertMethod == False:
                    filters.append(ConfigCheck.Method.ilike("%" + method + "%"))
                else:
                    filters.append(ConfigCheck.Method.notilike("%" + method + "%"))
            if len(key) > 0:
                if invertKey == False:
                    filters.append(ConfigCheck.Key.ilike("%" + key + "%"))
                else:
                    filters.append(ConfigCheck.Key.notilike("%" + key + "%"))
            if len(value) > 0:
                if invertValue == False:
                    filters.append(ConfigCheck.Value.ilike("%" + value + "%"))
                else:
                    filters.append(ConfigCheck.Value.notilike("%" + value + "%"))
            if len(result) > 0:
                if invertResult == False:
                    filters.append(ConfigCheck.Result.ilike("%" + result + "%"))
                else:
                    filters.append(ConfigCheck.Result.notilike("%" + result + "%"))
            if len(message) > 0:
                if invertMessage == False:
                    filters.append(ConfigCheck.Message.ilike("%" + message + "%"))
                else:
                    filters.append(ConfigCheck.Message.notilike("%" + message + "%"))

            checks = ConfigCheck.query.filter(*filters).all()
        else:
            checks = ConfigCheck.query.all()
        return render_template('configcheck_search_list.html', form=form, checks=checks)
    else:
        print('GET')
        checks = ConfigCheck.query.all()
        return render_template('configcheck_search_list.html', form=form, checks=checks)
