from flask import render_template, request, Response
from flask_login import login_required

from systemdb.webapp.sysinfo import sysinfo_bp

from systemdb.core.models.sysinfo import Host
from systemdb.core.models.sysinfo import Service
from systemdb.webapp.sysinfo.forms.services import ServiceSearchForm
from systemdb.core.export.excel.services import generate_services_excel


@sysinfo_bp.route('/services/', methods=['GET'])
@login_required
def service_list():
    services = Service.query.all()
    return render_template('service_list.html', services=services)


@sysinfo_bp.route('/services/search/', methods=['GET', 'POST'])
@login_required
def service_search_list():
    form = ServiceSearchForm()

    if request.method == 'POST':
        filters = []
        if form.validate_on_submit():
            name = form.Name.data
            systemname = form.SystemName.data
            displayname = form.DisplayName.data
            pathname = form.PathName.data
            started = form.Started.data
            startmode = form.StartMode.data
            startname = form.StartName.data
            invertName = form.InvertName.data
            invertDisplayName = form.InvertDisplayName.data
            invertSystemName = form.InvertSystemName.data
            invertPathName = form.InvertPathName.data
            invertStartMode = form.InvertStartMode.data
            invertStartName = form.InvertStartName.data

            if len(name) > 0 :
                if invertName == False:
                    filters.append(Service.Name.ilike("%"+name+"%"))
                else:
                    filters.append(Service.Name.notilike("%"+name+"%"))
            if len(systemname) > 0:
                if invertSystemName == False:
                    filters.append(Service.SystemName.ilike("%"+systemname+"%"))
                else:
                    filters.append(Service.SystemName.notilike("%"+systemname+"%"))
            if len(pathname) > 0 :
                if invertPathName == False:
                    filters.append(Service.PathName.ilike("%"+pathname+"%"))
                else:
                    filters.append(Service.PathName.notilike("%"+pathname+"%"))
            if len(startmode) > 0 :
                if invertStartMode == False:
                    filters.append(Service.StartMode.ilike("%"+startmode+"%"))
                else:
                    filters.append(Service.StartMode.notilike("%"+startmode+"%"))
            if len(startname) > 0 :
                if invertStartName == False:
                    filters.append(Service.StartName.ilike("%"+startname+"%"))
                else:
                    filters.append(Service.StartName.notilike("%"+startname+"%"))
            if len(displayname) > 0 :
                if invertDisplayName == False:
                    filters.append(Service.DisplayName.ilike("%"+displayname+"%"))
                else:
                    filters.append(Service.DisplayName.notilike("%"+displayname+"%"))
            if len(started) > 0 :
                filters.append(Service.Started.ilike("%"+started+"%"))

            services = Service.query.filter(*filters).all()

            if 'download' in request.form:
                output = generate_services_excel(services=services)
                return Response(output, mimetype="text/xslx",
                                headers={"Content-disposition": "attachment; filename=services.xlsx",
                                         "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})

        else:
            return render_template('service_search_list.html', form=form)
    else:
        services = []

    return render_template('service_search_list.html', form=form, services=services)


@sysinfo_bp.route('/services/<int:id>', methods=['GET'])
@login_required
def service_detail(id):
    service = Service.query.get_or_404(id)
    host = Host.query.get_or_404(service.Host_id)
    permissionStr = service.BinaryPermissionsStr.split("\n")if service.BinaryPermissionsStr is not None else ""
    return render_template("service_details.html", service=service, host=host, binaryPermissionStr=permissionStr)
