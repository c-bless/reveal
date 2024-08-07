from flask import render_template, Response, url_for, request
from flask_login import login_required
from sqlalchemy import and_
from reveal.webapp.sysinfo import sysinfo_bp
from reveal.core.export.excel.hosts import generate_hosts_excel
from reveal.core.export.excel.hosts import generate_hosts_excel_brief
from reveal.core.export.excel.usermgmt import generate_group_members_excel

from reveal.core.models.sysinfo import Host, Group
from reveal.core.reports import ReportInfo
from reveal.core.querries.usermgmt import find_groups_where_domadm_is_localadmin
from reveal.core.querries.usermgmt import find_groups_where_domadm_is_localadmin_with_host_filter
from reveal.core.querries.usermgmt import find_hosts_where_domadm_is_localadmin_with_host_filter
from reveal.core.querries.usermgmt import get_autologon_admin

from reveal.webapp.sysinfo.forms.report.DomAdminReport import DomAdminReportForm
from reveal.webapp.sysinfo.forms.report.AutoAdminReport import AutoAdminReportForm

from reveal.core.export.word.util import get_host_report_templates
from reveal.core.export.word.util import get_host_report_directory
from reveal.core.export.word.util import get_group_report_templates
from reveal.core.export.word.util import get_group_report_directory
from reveal.core.export.word.util import generate_hosts_report_docx
from reveal.core.export.word.util import generate_group_report_docx


####################################################################
# Hosts with Domain Admins in local admin group
####################################################################
@sysinfo_bp.route('/report/domainadmin', methods=['GET', 'POST'])
@login_required
def hosts_report_domainadmin():
    form = DomAdminReportForm()

    templates = get_group_report_templates()
    form.TemplateFile.choices = [(template, template) for template in templates]

    if request.method == 'POST':
        host_filter = []
        if form.validate_on_submit():
            systemgroup = form.SystemGroup.data
            location = form.Location.data
            selectedTemplate = form.TemplateFile.data
            label = form.Label.data

            invertSystemgroup = form.InvertSystemGroup.data
            invertLocation = form.InvertLocation.data
            invertLabel = form.InvertLabel.data

            if len(systemgroup) > 0:
                if not invertSystemgroup:
                    host_filter.append(Host.SystemGroup.ilike("%" + systemgroup + "%"))
                else:
                    host_filter.append(Host.SystemGroup.notilike("%" + systemgroup + "%"))
            if len(location) > 0:
                if not invertLocation:
                    host_filter.append(Host.Location.ilike("%" + location + "%"))
                else:
                    host_filter.append(Host.Location.notilike("%" + location + "%"))
            if len(label) > 0:
                if not invertLabel:
                    host_filter.append(Host.Label.ilike("%"+label+"%"))
                else:
                    host_filter.append(Host.Label.notilike("%"+label+"%"))

            groups = find_groups_where_domadm_is_localadmin_with_host_filter(host_filter=host_filter)

            if 'brief' in request.form:
                hosts = find_hosts_where_domadm_is_localadmin_with_host_filter(host_filter=host_filter)
                output = generate_hosts_excel_brief(hosts)
                return Response(output, mimetype="text/xslx",
                                headers={
                                    "Content-disposition": "attachment; filename=hosts_brief-domadmin.xlsx",
                                    "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                                })
            if 'full' in request.form:
                hosts = find_hosts_where_domadm_is_localadmin_with_host_filter(host_filter=host_filter)
                output = generate_hosts_excel(hosts)
                return Response(output, mimetype="text/xslx",
                                headers={
                                    "Content-disposition": "attachment; filename=hosts-domadmin.xlsx",
                                    "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                                })
            if 'memberships' in request.form:
                output = generate_group_members_excel(groups=groups)
                return Response(output, mimetype="text/xlsx",
                                headers={
                                    "Content-disposition": "attachment; filename=groups-with-domainadmin-brief.xlsx",
                                    "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                                })
            if 'word' in request.form:
                if selectedTemplate in templates:
                    template_dir = get_group_report_directory()
                    report = ReportDomAdminMemberOfLocalAdmin()
                    output = generate_group_report_docx(f"{template_dir}/{selectedTemplate}",
                                                        report, groups=groups)
                    return Response(output, mimetype="text/docx",
                                    headers={
                                        "Content-disposition": "attachment; filename={0}.docx".format(report.name)
                                    })
        else:
            groups = find_groups_where_domadm_is_localadmin()

    else:
        groups = find_groups_where_domadm_is_localadmin()

    return render_template('sysinfo/reports/group_members_list_search_report.html', groups=groups,
                           report_name="Domain Admins in local administrators group",
                           form=form)



class ReportDomAdminMemberOfLocalAdmin(ReportInfo):

    def __init__(self):
        super().initWithParams(
            name="Domain Admins in local administrators group",
            category="Hardening",
            tags=["Domain Admins", "Local Admins", "User Assignments", "MemberOf", "Admins",
                  "Admin Privileges"],
            description='Report all hosts where "Domain Admins" are members of the local administrators group',
            views=[("view", url_for('sysinfo.hosts_report_domainadmin'))]
        )


####################################################################
# Hosts with autologon user in local admin group
####################################################################
@sysinfo_bp.route('/report/autologonadmin', methods=['GET','POST'])
@login_required
def hosts_report_autologonadmin():
    form = AutoAdminReportForm()
    host_filter = []
    hosts = []
    templates = get_host_report_templates()
    form.TemplateFile.choices = [(template, template) for template in templates]

    if request.method == 'POST':
        if form.validate_on_submit():
            systemgroup = form.SystemGroup.data
            location = form.Location.data
            selectedTemplate = form.TemplateFile.data
            label = form.Label.data

            invertSystemgroup = form.InvertSystemGroup.data
            invertLocation = form.InvertLocation.data
            invertLabel = form.InvertLabel.data

            if len(systemgroup) > 0:
                if not invertSystemgroup:
                    host_filter.append(Host.SystemGroup.ilike("%" + systemgroup + "%"))
                else:
                    host_filter.append(Host.SystemGroup.notilike("%" + systemgroup + "%"))
            if len(location) > 0:
                if not invertLocation:
                    host_filter.append(Host.Location.ilike("%" + location + "%"))
                else:
                    host_filter.append(Host.Location.notilike("%" + location + "%"))
            if len(label) > 0:
                if not invertLabel:
                    host_filter.append(Host.Label.ilike("%"+label+"%"))
                else:
                    host_filter.append(Host.Label.notilike("%"+label+"%"))

            hosts = get_autologon_admin(host_filter=host_filter)

            if 'brief' in request.form:
                output = generate_hosts_excel_brief(hosts)
                return Response(output, mimetype="text/xlsx",
                                headers={
                                    "Content-disposition": "attachment; filename=hosts-with-autologonadmin-brief.xlsx",
                                    "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                                })
            if 'full' in request.form:
                output = generate_hosts_excel(hosts)
                return Response(output, mimetype="text/xlsx",
                                headers={
                                    "Content-disposition": "attachment; filename=hosts-with-autologonadmin-full.xlsx",
                                    "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                                })
            if 'word' in request.form:
                if selectedTemplate in templates:
                    template_dir = get_host_report_directory()
                    report = ReportAutologonIsLocalAdmin()
                    output = generate_hosts_report_docx(f"{template_dir}/{selectedTemplate}",
                                                        report, hosts=hosts)
                    return Response(output, mimetype="text/docx",
                                    headers={
                                        "Content-disposition": "attachment; filename={0}.docx".format(report.name)
                                    })
    else:
        hosts = get_autologon_admin()

    return render_template('sysinfo/reports/host_report_list.html', hosts=hosts, form=form,
                           report_name="Autologon as admin")


class ReportAutologonIsLocalAdmin(ReportInfo):

    def __init__(self):
        super().initWithParams(
            name="Autologon as admin",
            category="Hardening",
            tags=["Autologon", "Local Admins", "User Assignments", "MemberOf", "Admins",
                  "Admin Privileges"],
            description='Report all hosts where the autologon user is member of the local administrator group.',
            views=[("view",url_for("sysinfo.hosts_report_autologonadmin"))]
        )