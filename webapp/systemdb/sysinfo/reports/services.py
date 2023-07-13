from flask import render_template, Response, url_for, request
from flask_login import login_required

from sqlalchemy import and_

from webapp.systemdb.sysinfo import sysinfo_bp
from webapp.systemdb.sysinfo.export_func import generate_services_excel

from webapp.systemdb.models.sysinfo import Service, ServiceACL
from webapp.systemdb.sysinfo.forms.services import ServiceAclSearchForm, ServiceUserContextSearchForm

from webapp.systemdb.sysinfo.reports import ReportInfo
####################################################################
# Hosts with UQSP vulnerabilities
####################################################################
@sysinfo_bp.route('/report/services/uqsp/', methods=['GET'])
@login_required
def hosts_report_services_uqsp():
    services = Service.query.filter(and_(Service.PathName.notlike('"%'),
                                         Service.PathName.contains(" "),
                                         Service.PathName.notlike('C:\\Windows%'))).all()

    return render_template('service_list.html', services=services,
                           download_url=url_for("sysinfo.hosts_report_services_uqsp_excel"))


@sysinfo_bp.route('/report/services/uqsp/excel', methods=['GET'])
@login_required
def hosts_report_services_uqsp_excel():
    services = Service.query.filter(and_(Service.PathName.notlike('"%'),
                                         Service.PathName.contains(" "),
                                         Service.PathName.notlike('C:\\Windows%'))).all()

    output = generate_services_excel(services=services)
    return Response(output, mimetype="text/xlsx",
                    headers={"Content-disposition": "attachment; filename=usqp.xlsx",
                             "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" })



class ReportUQSP(ReportInfo):

    def __init__(self):
        super().initWithParams(
            name="UQSP",
            category="Systemhardening",
            tags=["Systemhardening", "Unqouted Service Pathes", "UQSP", "Service Misconfiguration"],
            description='Report all services where the path is not enclosed in quotes and which have a spaces in the path.',
            views=[("view", url_for("sysinfo.hosts_report_services_uqsp"))]
        )

####################################################################
# Services by ACL
####################################################################
@sysinfo_bp.route('/report/services/by-acl/', methods=['GET', 'POST'])
@login_required
def hosts_report_services_by_acl():
    form = ServiceAclSearchForm()

    if request.method == 'POST':
        if form.validate_on_submit():
            user = form.User.data
            invert_user = form.InvertUser.data
            permission = form.Permission.data
            invert_permission = form.InvertPermission.data
            if invert_user == False and invert_permission == False:
                acls = ServiceACL.query.filter(and_(ServiceACL.AccountName.ilike("%" + user + "%"),
                                                        ServiceACL.AccessRight.ilike("%" + permission + "%")
                                                        )).all()
            elif invert_user == False:
                acls = ServiceACL.query.filter(and_(ServiceACL.AccountName.ilike("%" + user + "%"),
                                                    ServiceACL.AccessRight.notilike("%" + permission + "%")
                                                    )).all()
            elif invert_permission == False:
                acls = ServiceACL.query.filter(and_(ServiceACL.AccountName.notilike("%" + user + "%"),
                                                    ServiceACL.AccessRight.ilike("%" + permission + "%")
                                                    )).all()
            else:
                acls = ServiceACL.query.filter(and_(ServiceACL.AccountName.notilike("%" + user + "%"),
                                                    ServiceACL.AccessRight.notilike("%" + permission + "%")
                                                    )).all()
            return render_template('service_acl_search_list.html', form=form, acls=acls)
        else:
            print("Invalid input")
            return render_template('service_acl_search_list.html', form=form)
    else:
        return render_template('service_acl_search_list.html', form=form)


class ReportServiceByPermission(ReportInfo):

    def __init__(self):
        super().initWithParams(
            name="Service by ACL",
            category="Systemhardening",
            tags=["Systemhardening", "ACL", "User Permissions"],
            description='Report all services where the ACLs match specified User and Permission.',
            views=[("view", url_for("sysinfo.hosts_report_services_by_acl"))]
        )

####################################################################
# Services by user context
####################################################################
@sysinfo_bp.route('/report/services/by-usercontext/', methods=['GET', 'POST'])
@login_required
def hosts_report_services_by_usercontext():
    form = ServiceUserContextSearchForm()

    if request.method == 'POST':
        if form.validate_on_submit():
            startname = form.Startname.data
            invert = form.Invert.data
            if invert == False:
                services = Service.query.filter(Service.StartName.ilike("%" + startname + "%")).all()
            else:
                services = Service.query.filter(Service.StartName.notilike("%" + startname + "%")).all()
            return render_template('service_search_list.html',
                                   form=form,
                                   services=services,
                                   download_url=url_for("sysinfo.hosts_report_services_uqsp_excel"))
        else:
            print("Invalid input")
            return render_template('service_search_list.html',
                                   form=form,
                                   download_url=url_for("sysinfo.hosts_report_services_uqsp_excel"))
    else:
        return render_template('service_startnamesearch_list.html',
                               form=form,
                               download_url=url_for("sysinfo.hosts_report_services_uqsp_excel"))

class ReportServiceByUsercontext(ReportInfo):

    def __init__(self):
        super().initWithParams(
            name="Service by user context (Startname)",
            category="Systemhardening",
            tags=["Systemhardening", "User Context", "User Permissions"],
            description='Report all services executed in context of specified user.',
            views=[("view", url_for("sysinfo.hosts_report_services_by_usercontext"))]
        )
