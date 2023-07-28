from flask import render_template, request, Response
from flask_login import login_required

from systemdb.webapp.sysinfo import sysinfo_bp

from systemdb.core.models.sysinfo import ConfigCheck
from systemdb.core.models.sysinfo import RegistryCheck
from systemdb.webapp.sysinfo.forms.checks import ConfigCheckSearchForm
from systemdb.webapp.sysinfo.forms.checks import RegistryCheckSearchForm


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
        checks = ConfigCheck.query.all()
        return render_template('configcheck_search_list.html', form=form, checks=checks)


@sysinfo_bp.route('/checks/registry', methods=['GET', 'POST'])
@login_required
def registrycheck_search_list():
    form = RegistryCheckSearchForm()

    if request.method == 'POST':
        filters = []
        if form.validate_on_submit():
            name = form.Name.data
            category = form.Category.data
            description = form.Description.data
            tags = form.Tags.data
            expected = form.Expected.data
            path = form.Path.data
            key = form.Key.data
            keyExists = form.KeyExists.data
            valueMatch = form.ValueMatch.data
            currentValue = form.CurrentValue.data
            invertName = form.InvertName.data
            invertCategory = form.InvertCategory.data
            invertDescription = form.InvertDescription.data
            invertPath = form.InvertPath.data
            invertKey = form.InvertKey.data
            invertTags = form.InvertTags.data
            invertCurrentValue = form.InvertCurrentValue.data
            invertExpected = form.InvertExpected.data
            useKeyExist = form.UseKeyExists.data
            useValueMatch = form.UseValueMatch


            if len(name) > 0:
                if invertName == False:
                    filters.append(RegistryCheck.Name.ilike("%" + name + "%"))
                else:
                    filters.append(RegistryCheck.Name.notilike("%" + name + "%"))
            if len(category) > 0:
                if invertCategory == False:
                    filters.append(RegistryCheck.Category.ilike("%" + category + "%"))
                else:
                    filters.append(RegistryCheck.Category.notilike("%" + category + "%"))
            if len(description) > 0:
                if invertDescription == False:
                    filters.append(RegistryCheck.Description.ilike("%" + description + "%"))
                else:
                    filters.append(RegistryCheck.Description.notilike("%" + description + "%"))
            if len(tags) > 0:
                if invertTags == False:
                    filters.append(RegistryCheck.Tags.ilike("%" + tags + "%"))
                else:
                    filters.append(RegistryCheck.Tags.notilike("%" + tags + "%"))
            if len(expected) > 0:
                if invertExpected == False:
                    filters.append(RegistryCheck.Expected.ilike("%" + expected + "%"))
                else:
                    filters.append(RegistryCheck.Expected.notilike("%" + expected + "%"))
            if len(path) > 0:
                if invertPath == False:
                    filters.append(RegistryCheck.Path.ilike("%" + path + "%"))
                else:
                    filters.append(RegistryCheck.Path.notilike("%" + path + "%"))
            if len(key) > 0:
                if invertKey == False:
                    filters.append(RegistryCheck.Key.ilike("%" + key + "%"))
                else:
                    filters.append(RegistryCheck.Key.notilike("%" + key + "%"))
            if len(currentValue) > 0:
                if invertCurrentValue == False:
                    filters.append(RegistryCheck.Message.ilike("%" + currentValue + "%"))
                else:
                    filters.append(RegistryCheck.Message.notilike("%" + currentValue + "%"))
            if useValueMatch:
                filters.append(RegistryCheck.ValueMatch == valueMatch)
            if useKeyExist:
                filters.append(RegistryCheck.KeyExists == keyExists)
            checks = RegistryCheck.query.filter(*filters).all()
        else:
            checks = RegistryCheck.query.all()
        return render_template('registrycheck_search_list.html', form=form, checks=checks)
    else:
        print('GET')
        checks = RegistryCheck.query.all()
        return render_template('registrycheck_search_list.html', form=form, checks=checks)
