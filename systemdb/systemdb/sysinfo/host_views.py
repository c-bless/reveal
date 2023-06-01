from flask import render_template, url_for
from sqlalchemy import desc

from . import sysinfo_bp

from ..core.sysinfo_models import Host, Group, User, Service, Share, Product


@sysinfo_bp.route('/hosts/', methods=['GET'])
def host_list():
    hosts = Host.query.all()
    return render_template('host_list.html', hosts=hosts, download_url=url_for("sysinfo.hosts_export_excel"))


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
