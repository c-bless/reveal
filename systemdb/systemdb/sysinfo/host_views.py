from flask import render_template, url_for, request
from sqlalchemy import desc,and_

from . import sysinfo_bp

from ..models.sysinfo import Host, Group, User, Service, Share, Product
from ..models.eol import EoL
from .forms.hosts import HostSearchForm


@sysinfo_bp.route('/hosts/', methods=['GET'])
def host_list():
    hosts = Host.query.all()
    return render_template('host_list.html', hosts=hosts, download_url=url_for("sysinfo.hosts_export_excel"))

@sysinfo_bp.route('/hosts/search/', methods=['GET', 'POST'])
def host_search_list():
    form = HostSearchForm()

    if request.method == 'POST':
        filters = []
        hostname = form.Hostname.data
        domain = form.Domain.data
        domainRole = form.DomainRole.data
        osVersion = form.OSVersion.data
        osBuildNumber = form.OSBuildNumber.data
        osName = form.OSName.data
        systemgroup = form.SystemGroup.data
        location = form.Location.data

        invertHostname = form.InvertHostname.data
        invertDomain = form.InvertDomain.data
        invertDomainRole = form.InvertDomainRole.data
        invertOsVersion = form.InvertOSVersion.data
        invertOsBuildNumber = form.InvertOSBuildNumber.data
        invertOsName = form.InvertOSName.data
        invertSystemgroup = form.InvertSystemGroup.data
        invertLocation = form.InvertLocation.data

        if len(hostname) > 0 :
            if invertHostname == False:
                filters.append(Host.Hostname.ilike("%"+hostname+"%"))
            else:
                filters.append(Host.Hostname.notilike("%"+hostname+"%"))
        if len(domain) > 0:
            if invertDomain == False:
                filters.append(Host.Domain.ilike("%"+domain+"%"))
            else:
                filters.append(Host.Domain.notilike("%"+domain+"%"))
        if len(domainRole) > 0:
            if invertDomainRole == False:
                filters.append(Host.DomainRole.ilike("%"+domainRole+"%"))
            else:
                filters.append(Host.DomainRole.notilike("%"+domainRole+"%"))
        if len(osVersion) > 0:
            if invertOsVersion == False:
                filters.append(Host.OSVersion.ilike("%"+osVersion+"%"))
            else:
                filters.append(Host.OSVersion.notilike("%"+osVersion+"%"))
        if len(osBuildNumber) > 0:
            if invertOsBuildNumber == False:
                filters.append(Host.OSBuildNumber.ilike("%"+osBuildNumber+"%"))
            else:
                filters.append(Host.OSBuildNumber.notilike("%"+osBuildNumber+"%"))
        if len(osName) > 0:
            if invertOsName == False:
                filters.append(Host.OSName.ilike("%"+osName+"%"))
            else:
                filters.append(Host.OSName.notilike("%"+osName+"%"))
        if len(systemgroup) > 0:
            if invertSystemgroup == False:
                filters.append(Host.SystemGroup.ilike("%"+systemgroup+"%"))
            else:
                filters.append(Host.SystemGroup.notilike("%"+systemgroup+"%"))
        if len(location) > 0:
            if invertSystemgroup == False:
                filters.append(Host.Location.ilike("%"+location+"%"))
            else:
                filters.append(Host.Location.notilike("%"+location+"%"))
        hosts = Host.query.filter(and_(*filters)).all()
    else:
        hosts = Host.query.all()

    return render_template('host_search_list.html', form=form, hosts=hosts, download_url=url_for("sysinfo.hosts_export_excel"))


@sysinfo_bp.route('/hosts/<int:id>', methods=['GET'])
def host_detail(id):
    host = Host.query.get_or_404(id)
    return render_template('host_details.html', host=host)


@sysinfo_bp.route('/hosts/<int:id>/services/', methods=['GET'])
def host_service_list(id):
    services = Service.query.filter(Service.Host_id == id).all()
    return render_template('service_list.html', services=services)


@sysinfo_bp.route('/services/', methods=['GET'])
def service_list():
    services = Service.query.all()
    return render_template('service_list.html', services=services)


@sysinfo_bp.route('/services/<int:id>', methods=['GET'])
def service_detail(id):
    service = Service.query.get_or_404(id)
    host = Host.query.get_or_404(service.Host_id)
    permissionStr = service.BinaryPermissionsStr.split("\n")if service.BinaryPermissionsStr is not None else ""
    return render_template("service_details.html", service=service, host=host, binaryPermissionStr=permissionStr)


@sysinfo_bp.route('/products/', methods=['GET'])
def product_list():
    products = Product.query.all()
    return render_template('product_list.html', products=products)


@sysinfo_bp.route('/groups/<int:id>', methods=['GET'])
def group_detail(id):
    group = Group.query.get_or_404(id)
    host = Host.query.get_or_404(group.Host_id)
    return render_template("group_details.html", group=group, host=host)


@sysinfo_bp.route('/users/<int:id>', methods=['GET'])
def user_detail(id):
    user = User.query.get_or_404(id)
    host = Host.query.get_or_404(user.Host_id)
    return render_template("user_details.html", user=user, host=host)


@sysinfo_bp.route('/shares/<int:id>', methods=['GET'])
def share_detail(id):
    share = Share.query.get_or_404(id)
    host = Host.query.get_or_404(share.Host_id)
    ntfs_permissions = share.NTFSPermission.split("\n") if share.NTFSPermission is not None else ""
    share_permissions = share.SharePermission.split("\n") if share.SharePermission is not None else ""
    return render_template("share_details.html", share=share, host=host, ntfs_permissions=ntfs_permissions, share_permissions=share_permissions)
