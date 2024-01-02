from flask import render_template, request, Response
from flask_login import login_required

from reveal.webapp.sysinfo import sysinfo_bp

from reveal.core.models.sysinfo import Host
from reveal.core.models.sysinfo import Service
from reveal.webapp.sysinfo.forms.services import ServiceSearchForm
from reveal.core.export.excel.services import generate_services_excel


@sysinfo_bp.route('/services/', methods=['GET'])
@login_required
def service_list():
    services = Service.query.all()
    return render_template('sysinfo/service/service_list.html', services=services)


@sysinfo_bp.route('/services/search/', methods=['GET', 'POST'])
@login_required
def service_search_list():
    form = ServiceSearchForm()

    if request.method == 'POST':
        service_filter = []
        if form.validate_on_submit():
            name = form.Name.data
            systemname = form.SystemName.data
            displayname = form.DisplayName.data
            pathname = form.PathName.data
            started = form.Started.data
            useStarted = form.UseStarted.data
            startmode = form.StartMode.data
            startname = form.StartName.data
            invertName = form.InvertName.data
            invertDisplayName = form.InvertDisplayName.data
            invertSystemName = form.InvertSystemName.data
            invertPathName = form.InvertPathName.data
            invertStartMode = form.InvertStartMode.data
            invertStartName = form.InvertStartName.data

            if len(name) > 0 :
                if not invertName:
                    service_filter.append(Service.Name.ilike("%"+name+"%"))
                else:
                    service_filter.append(Service.Name.notilike("%"+name+"%"))
            if len(systemname) > 0:
                if not invertSystemName:
                    service_filter.append(Service.SystemName.ilike("%"+systemname+"%"))
                else:
                    service_filter.append(Service.SystemName.notilike("%"+systemname+"%"))
            if len(pathname) > 0 :
                if not invertPathName:
                    service_filter.append(Service.PathName.ilike("%"+pathname+"%"))
                else:
                    service_filter.append(Service.PathName.notilike("%"+pathname+"%"))
            if len(startmode) > 0 :
                if not invertStartMode:
                    service_filter.append(Service.StartMode.ilike("%"+startmode+"%"))
                else:
                    service_filter.append(Service.StartMode.notilike("%"+startmode+"%"))
            if len(startname) > 0 :
                if not invertStartName:
                    service_filter.append(Service.StartName.ilike("%"+startname+"%"))
                else:
                    service_filter.append(Service.StartName.notilike("%"+startname+"%"))
            if len(displayname) > 0 :
                if not invertDisplayName:
                    service_filter.append(Service.DisplayName.ilike("%"+displayname+"%"))
                else:
                    service_filter.append(Service.DisplayName.notilike("%"+displayname+"%"))
            if useStarted:
                service_filter.append(Service.Started == started)

            services = Service.query.filter(*service_filter).all()

            if 'download' in request.form:
                output = generate_services_excel(services=services)
                return Response(output, mimetype="text/xslx",
                                headers={"Content-disposition": "attachment; filename=services.xlsx",
                                         "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})

        else:
            return render_template('sysinfo/service/service_search_list.html', form=form)
    else:
        services = []

    return render_template('sysinfo/service/service_search_list.html', form=form, services=services)


@sysinfo_bp.route('/services/<int:id>', methods=['GET'])
@login_required
def service_detail(id):
    service = Service.query.get_or_404(id)
    host = Host.query.get_or_404(service.Host_id)
    permissionStr = service.BinaryPermissionsStr.split("\n")if service.BinaryPermissionsStr is not None else ""
    return render_template("sysinfo/service/service_details.html", service=service, host=host, binaryPermissionStr=permissionStr)
