from flask import render_template
from flask import request
from flask import Response
from flask_login import login_required
from sqlalchemy import and_

from reveal.core.models.activedirectory import ADUser
from reveal.core.models.activedirectory import ADGroup
from reveal.core.models.activedirectory import ADDomain
from reveal.webapp.ad.forms.users import ADUserSearchForm
from reveal.webapp.ad.forms.groups import ADGroupSearchForm
from reveal.core.export.excel.ad import generate_user_excel
from reveal.core.export.excel.ad import generate_group_excel

from reveal.webapp.ad import ad_bp


@ad_bp.route('/ad/users', methods=['GET'])
@login_required
def user_list():
    users = ADUser.query.all()
    return render_template('ad/user/aduser_list.html', users=users)


@ad_bp.route('/ad/domain/<int:id>/users', methods=['GET'])
@login_required
def user_by_domain_list(id):
    users = ADUser.query.filter(ADUser.Domain_id == id)
    return render_template('ad/user/aduser_list.html', users=users)


@ad_bp.route('/ad/user/<int:id>', methods=['GET'])
@login_required
def user_detail(id):
    user = ADUser.query.get_or_404(id)
    return render_template('ad/user/aduser_details.html', user=user)


@ad_bp.route('/ad/user/search/', methods=['GET', 'POST'])
@login_required
def user_search_list():
    form = ADUserSearchForm()

    if request.method == 'POST':
        filters = []
        if form.validate_on_submit():
            SAMAccountName = form.SAMAccountName.data
            SID = form.SID.data
            GivenName = form.GivenName.data
            distinguishedName = form.DistinguishedName.data
            domain = form.Domain.data
            Surname = form.Surname.data
            Name = form.Name.data
            Enabled =  form.Enabled.data
            Disabled =  form.Disabled.data

            LockedOut_True =  form.LockedOut_True.data
            LockedOut_False =  form.LockedOut_False.data

            invertSAMAccountName = form.InvertSAMAccountName.data
            invertSID = form.InvertSID.data
            invertGivenName = form.InvertGivenName.data
            invertDomain = form.InvertDomain.data
            invertDistinguishedName = form.InvertDistinguishedName.data
            invertName = form.InvertName.data
            invertSurname = form.InvertGivenName.data

            if len(SAMAccountName) > 0 :
                if not invertSAMAccountName:
                    filters.append(ADUser.SAMAccountName.ilike("%"+SAMAccountName+"%"))
                else:
                    filters.append(ADUser.SAMAccountName.notilike("%"+SAMAccountName+"%"))
            if len(SID) > 0:
                if not invertSID:
                    filters.append(ADUser.SID.ilike("%"+SID+"%"))
                else:
                    filters.append(ADUser.SID.notilike("%"+SID+"%"))
            if len(GivenName) > 0:
                if invertGivenName == False:
                    filters.append(ADUser.GivenName.ilike("%"+GivenName+"%"))
                else:
                    filters.append(ADUser.GivenName.notilike("%"+GivenName+"%"))
            if len(Surname) > 0:
                if invertSurname == False:
                    filters.append(ADUser.Surname.ilike("%"+Surname+"%"))
                else:
                    filters.append(ADUser.Surname.notilike("%"+Surname+"%"))
            if len(Name) > 0:
                if invertName == False:
                    filters.append(ADUser.Name.ilike("%"+Name+"%"))
                else:
                    filters.append(ADUser.Name.notilike("%"+Name+"%"))
            if len(domain) > 0:
                if invertDomain == False:
                    ids = [d.id for d in  ADDomain.query.filter(ADDomain.Name.ilike("%"+domain+"%")).all()]
                    filters.append(ADUser.Domain_id.in_(ids))
                else:
                    ids = [d.id for d in  ADDomain.query.filter(ADDomain.Name.notilike("%"+domain+"%")).all()]
                    filters.append(ADUser.Domain_id.in_(ids))
            if len(distinguishedName) > 0:
                if invertDistinguishedName == False:
                    filters.append(ADUser.DistinguishedName.ilike("%"+distinguishedName+"%"))
                else:
                    filters.append(ADUser.DistinguishedName.notilike("%"+distinguishedName+"%"))
            if Enabled:
                filters.append(ADUser.Enabled == True)
            if Disabled:
                filters.append(ADUser.Enabled == False)
            if LockedOut_True:
                filters.append(ADUser.LockedOut == True)
            if LockedOut_False:
                filters.append(ADUser.LockedOut == False)

            users = ADUser.query.filter(and_(*filters)).all()

            if 'download' in request.form:
                output = generate_user_excel(user_list=users)
                return Response(output, mimetype="text/xslx",
                                headers={"Content-disposition": "attachment; filename=domain-user.xlsx",
                                         "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})

        else:
            return render_template('ad/user/aduser_search_list.html', form=form)
    else:
        # users = ADUser.query.all()
        users = []

    return render_template('ad/user/aduser_search_list.html', form=form, users=users)


@ad_bp.route('/ad/groups', methods=['GET'])
@login_required
def groups_list():
    groups = ADGroup.query.all()
    return render_template('ad/group/adgroup_list.html', groups=groups)


@ad_bp.route('/ad/views/<int:id>/groups', methods=['GET'])
@login_required
def groups_by_domain_list(id):
    groups = ADGroup.query.filter(ADGroup.Domain_id==id).all()
    return render_template('ad/group/adgroup_list.html', groups=groups)


@ad_bp.route('/ad/group/<int:id>', methods=['GET'])
@login_required
def group_detail(id):
    group = ADGroup.query.get_or_404(id)
    domain = ADDomain.query.filter(ADDomain.id == group.Domain_id).first()
    return render_template('ad/group/adgroup_details.html', group=group, domain=domain)


@ad_bp.route('/ad/group/search/', methods=['GET', 'POST'])
@login_required
def group_search_list():
    form = ADGroupSearchForm()

    if request.method == 'POST':
        filters = []
        if form.validate_on_submit():
            samAccountName = form.SAMAccountName.data
            sid = form.SID.data
            group_category = form.GroupCategory.data
            group_scope = form.GroupScope.data
            domain = form.Domain.data
            cn = form.CN.data

            invertSAMAccountName = form.InvertSAMAccountName.data
            invertSID = form.InvertSID.data
            invertGroupCategory = form.InvertGroupCategory.data
            invertGroupScope = form.InvertGroupScope.data
            invertDomain = form.InvertDomain.data
            invertCN = form.InvertCN.data

            if len(samAccountName) > 0 :
                if not invertSAMAccountName:
                    filters.append(ADGroup.SamAccountName.ilike("%"+samAccountName+"%"))
                else:
                    filters.append(ADGroup.SamAccountName.notilike("%"+samAccountName+"%"))
            if len(sid) > 0:
                if not invertSID:
                    filters.append(ADGroup.SID.ilike("%"+sid+"%"))
                else:
                    filters.append(ADGroup.SID.notilike("%"+sid+"%"))
            if len(group_category) > 0:
                if not invertGroupCategory:
                    filters.append(ADGroup.GroupCategory.ilike("%"+group_category+"%"))
                else:
                    filters.append(ADGroup.GroupCategory.notilike("%"+group_category+"%"))
            if len(group_scope) > 0:
                if not invertGroupScope:
                    filters.append(ADGroup.GroupScope.ilike("%"+group_scope+"%"))
                else:
                    filters.append(ADGroup.GroupScope.notilike("%"+group_scope+"%"))
            if cn and len(cn) > 0:
                if invertCN == False:
                    filters.append(ADGroup.CN.ilike("%"+cn+"%"))
                else:
                    filters.append(ADGroup.CN.notilike("%"+cn+"%"))
            if len(domain) > 0:
                if invertDomain == False:
                    ids = [d.id for d in  ADDomain.query.filter(ADDomain.Name.ilike("%"+domain+"%")).all()]
                    filters.append(ADGroup.Domain_id.in_(ids))
                else:
                    ids = [d.id for d in  ADDomain.query.filter(ADDomain.Name.notilike("%"+domain+"%")).all()]
                    filters.append(ADGroup.Domain_id.in_(ids))

            groups = ADGroup.query.filter(and_(*filters)).all()

            if 'download' in request.form:
                output = generate_group_excel(group_list=groups)
                return Response(output, mimetype="text/xslx",
                                headers={"Content-disposition": "attachment; filename=domain-groups.xlsx",
                                         "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})
        else:
            return render_template('ad/group/adgroup_search_list.html', form=form)
    else:
        groups = []

    return render_template('ad/group/adgroup_search_list.html', form=form, groups=groups)
