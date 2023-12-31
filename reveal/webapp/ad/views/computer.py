from flask import render_template
from flask import request
from flask import Response
from flask_login import login_required
from sqlalchemy import and_

from reveal.core.models.activedirectory import ADDomain
from reveal.core.models.activedirectory import ADComputer
from reveal.core.models.activedirectory import ADDomainController
from reveal.core.models.activedirectory import ADForestGlobalCatalog
from reveal.core.export.excel.ad import generate_computer_excel
from reveal.core.export.excel.ad import generate_dc_list_excel

from reveal.webapp.ad.forms.computer import ADComputerSearchForm
from reveal.webapp.ad.forms.computer import DCSearchForm

from reveal.webapp.ad import ad_bp

@ad_bp.route('/ad/dclist', methods=['GET'])
@login_required
def dc_list():
    dc_list = ADDomainController.query.all()
    return render_template('ad/computer/addc_list.html', dc_list=dc_list)


@ad_bp.route('/ad/gclist', methods=['GET'])
@login_required
def gc_list():
    gc_list = ADForestGlobalCatalog.query.all()
    return render_template('ad/computer/adgc_list.html', gc_list=gc_list)


@ad_bp.route('/ad/computer', methods=['GET'])
@login_required
def computer_list():
    computer_list = ADComputer.query.all()
    return render_template('ad/computer/adcomputer_list.html', computer_list=computer_list)


@ad_bp.route('/ad/domain/<int:id>/computer', methods=['GET'])
@login_required
def computer_by_domain_list(id):
    computer_list = ADComputer.query.filter(ADComputer.Domain_id==id)
    return render_template('ad/computer/adcomputer_list.html', computer_list=computer_list)

@ad_bp.route('/ad/computer/<int:id>', methods=['GET'])
@login_required
def computer_detail(id):
    computer = ADComputer.query.get_or_404(id)
    return render_template('ad/computer/adcomputer_details.html', computer=computer)



@ad_bp.route('/ad/computer/search/', methods=['GET', 'POST'])
@login_required
def computer_search_list():
    form = ADComputerSearchForm()

    if request.method == 'POST':
        filters = []
        if form.validate_on_submit():
            SAMAccountName = form.SamAccountName.data
            SID = form.SID.data
            DNSHostName = form.DNSHostName.data
            OperatingSystem = form.OperatingSystem.data
            distinguishedName = form.DistinguishedName.data
            domain = form.Domain.data
            IPv4Address = form.IPv4Address.data
            IPv6Address = form.IPv6Address.data
            Enabled =  form.Enabled.data
            Disabled =  form.Disabled.data

            invertSID = form.InvertSID.data
            invertSAMAccountName = form.InvertSamAccountName.data
            invertDNSHostName = form.InvertDNSHostName.data
            invertOperatingSystem = form.InvertOperatingSystem.data
            invertDomain = form.InvertDomain.data
            invertDistinguishedName = form.InvertDistinguishedName.data
            invertIPv4Address = form.InvertIPv4Address.data
            invertIPv6Address = form.InvertIPv6Address.data

            if len(SAMAccountName) > 0 :
                if not invertSAMAccountName:
                    filters.append(ADComputer.SamAccountName.ilike("%"+SAMAccountName+"%"))
                else:
                    filters.append(ADComputer.SamAccountName.notilike("%"+SAMAccountName+"%"))
            if len(DNSHostName) > 0:
                if not invertDNSHostName:
                    filters.append(ADComputer.DNSHostName.ilike("%"+DNSHostName+"%"))
                else:
                    filters.append(ADComputer.DNSHostName.notilike("%"+DNSHostName+"%"))
            if len(SID) > 0:
                if not invertSID:
                    filters.append(ADComputer.SID.ilike("%"+SID+"%"))
                else:
                    filters.append(ADComputer.SID.notilike("%"+SID+"%"))
            if len(OperatingSystem) > 0:
                if not invertOperatingSystem:
                    filters.append(ADComputer.OperatingSystem.ilike("%"+OperatingSystem+"%"))
                else:
                    filters.append(ADComputer.OperatingSystem.notilike("%"+OperatingSystem+"%"))
            if len(IPv4Address) > 0:
                if not invertIPv4Address:
                    filters.append(ADComputer.IPv4Address.ilike("%"+IPv4Address+"%"))
                else:
                    filters.append(ADComputer.IPv4Address.notilike("%"+IPv4Address+"%"))
            if len(IPv6Address) > 0:
                if not invertIPv6Address:
                    filters.append(ADComputer.IPv6Address.ilike("%"+IPv6Address+"%"))
                else:
                    filters.append(ADComputer.IPv6Address.notilike("%"+IPv6Address+"%"))
            if len(domain) > 0:
                if invertDomain == False:
                    ids = [d.id for d in  ADDomain.query.filter(ADDomain.Name.ilike("%"+domain+"%")).all()]
                    filters.append(ADComputer.Domain_id.in_(ids))
                else:
                    ids = [d.id for d in  ADDomain.query.filter(ADDomain.Name.notilike("%"+domain+"%")).all()]
                    filters.append(ADComputer.Domain_id.in_(ids))
            if len(distinguishedName) > 0:
                if invertDistinguishedName == False:
                    filters.append(ADComputer.DistinguishedName.ilike("%"+distinguishedName+"%"))
                else:
                    filters.append(ADComputer.DistinguishedName.notilike("%"+distinguishedName+"%"))
            if Enabled:
                filters.append(ADComputer.Enabled == True)
            if Disabled:
                filters.append(ADComputer.Enabled == False)

            computer_list = ADComputer.query.filter(and_(*filters)).all()

            if 'download' in request.form:
                output = generate_computer_excel(computer_list=computer_list)
                return Response(output, mimetype="text/xslx",
                                headers={"Content-disposition": "attachment; filename=domain-computer.xlsx",
                                         "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})

        else:
            return render_template('ad/computer/adcomputer_search_list.html', form=form)
    else:
        computer_list = []

    return render_template('ad/computer/adcomputer_search_list.html', form=form, computer_list=computer_list)




@ad_bp.route('/ad/dc/<int:id>/', methods=['GET'])
@login_required
def dc_detail(id):
    dc = ADDomainController.query.get_or_404(id)
    return render_template('ad/computer/addc_details.html', dc=dc)


@ad_bp.route('/ad/dc/search/', methods=['GET', 'POST'])
@login_required
def dc_search_list():
    form = DCSearchForm()

    if request.method == 'POST':
        filters = []
        if form.validate_on_submit():
            Hostname = form.Hostname.data
            OperatingSystem = form.OperatingSystem.data
            distinguishedName = form.DistinguishedName.data
            domain = form.Domain.data
            IPv4Address = form.IPv4Address.data
            IPv6Address = form.IPv6Address.data
            Enabled =  form.Enabled.data
            Disabled =  form.Disabled.data

            ldap_port = form.LDAP_port.data
            ssl_port = form.SSL_port.data
            GlobalCatalog_True =  form.GlobalCatalog_True.data
            GlobalCatalog_False =  form.GlobalCatalog_False.data

            invertHostname = form.InvertHostname.data
            invertOperatingSystem = form.InvertOperatingSystem.data
            invertDomain = form.InvertDomain.data
            invertDistinguishedName = form.InvertDistinguishedName.data
            invertIPv4Address = form.InvertIPv4Address.data
            invertIPv6Address = form.InvertIPv6Address.data
            invertLDAPport = form.InvertLDAP_port.data
            invertSSLport = form.InvertSSL_port.data

            if len(Hostname) > 0 :
                if not invertHostname:
                    filters.append(ADDomainController.Hostname.ilike("%"+Hostname+"%"))
                else:
                    filters.append(ADDomainController.Hostname.notilike("%"+Hostname+"%"))
            if len(OperatingSystem) > 0:
                if not invertOperatingSystem:
                    filters.append(ADDomainController.OperatingSystem.ilike("%"+OperatingSystem+"%"))
                else:
                    filters.append(ADDomainController.OperatingSystem.notilike("%"+OperatingSystem+"%"))
            if len(IPv4Address) > 0:
                if not invertIPv4Address:
                    filters.append(ADDomainController.IPv4Address.ilike("%"+IPv4Address+"%"))
                else:
                    filters.append(ADDomainController.IPv4Address.notilike("%"+IPv4Address+"%"))
            if len(IPv6Address) > 0:
                if not invertIPv6Address:
                    filters.append(ADDomainController.IPv6Address.ilike("%"+IPv6Address+"%"))
                else:
                    filters.append(ADDomainController.IPv6Address.notilike("%"+IPv6Address+"%"))
            if len(domain) > 0:
                if invertDomain == False:
                    ids = [d.id for d in  ADDomain.query.filter(ADDomain.Name.ilike("%"+domain+"%")).all()]
                    filters.append(ADDomainController.Domain_id.in_(ids))
                else:
                    ids = [d.id for d in  ADDomain.query.filter(ADDomain.Name.notilike("%"+domain+"%")).all()]
                    filters.append(ADDomainController.Domain_id.in_(ids))
            if len(distinguishedName) > 0:
                if invertDistinguishedName == False:
                    filters.append(ADDomainController.DistinguishedName.ilike("%"+distinguishedName+"%"))
                else:
                    filters.append(ADDomainController.DistinguishedName.notilike("%"+distinguishedName+"%"))
            if Enabled:
                filters.append(ADDomainController.Enabled == True)
            if Disabled:
                filters.append(ADDomainController.Enabled == False)
            if GlobalCatalog_True:
                filters.append(ADDomainController.GlobalCatalog_True == True)
            if GlobalCatalog_False:
                filters.append(ADDomainController.GlobalCatalog_False == False)
            if ldap_port:
                if not invertLDAPport:
                    filters.append(ADDomainController.LdapPort == ldap_port)
            if ssl_port:
                if not invertSSLport:
                    filters.append(ADDomainController.SslPort == ssl_port)

            dc_list = ADDomainController.query.filter(and_(*filters)).all()

            if 'download' in request.form:
                output = generate_dc_list_excel(dc_list=dc_list)
                return Response(output, mimetype="text/xslx",
                                headers={"Content-disposition": "attachment; filename=domain-DCs.xlsx",
                                         "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})

        else:
            return render_template('ad/computer/addc_search_list.html', form=form)
    else:
        dc_list = []

    return render_template('ad/computer/addc_search_list.html', form=form, dc_list=dc_list)
