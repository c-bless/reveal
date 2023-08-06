from flask import render_template
from flask import request
from flask import Response
from flask_login import login_required
from sqlalchemy import and_

from systemdb.core.models.activedirectory import ADDomain
from systemdb.core.models.activedirectory import ADTrust
from systemdb.core.export.excel.ad import generate_trust_excel

from systemdb.webapp.ad.forms.trusts import ADTrustSearchForm

from systemdb.webapp.ad import ad_bp


@ad_bp.route('/ad/trusts', methods=['GET'])
@login_required
def trust_list():
    trusts = ADTrust.query.all()
    return render_template('adtrust_list.html', trusts=trusts)


@ad_bp.route('/ad/trusts/search/', methods=['GET', 'POST'])
@login_required
def trust_search_list():
    form = ADTrustSearchForm()

    if request.method == 'POST':
        filters = []
        if form.validate_on_submit():
            source = form.Source.data
            target = form.Target.data
            direction = form.Direction.data
            distinguishedName = form.DistinguishedName.data
            domain = form.Domain.data

            invertSource = form.InvertSource.data
            invertTarget = form.InvertTarget.data
            invertDirection = form.InvertDirection.data
            invertDomain = form.InvertDomain.data
            invertDistinguishedName = form.InvertDistinguishedName.data

            if len(source) > 0 :
                if not invertSource:
                    filters.append(ADTrust.Source.ilike("%"+source+"%"))
                else:
                    filters.append(ADTrust.Source.notilike("%"+source+"%"))
            if len(target) > 0:
                if not invertTarget:
                    filters.append(ADTrust.Target.ilike("%"+target+"%"))
                else:
                    filters.append(ADTrust.Target.notilike("%"+target+"%"))
            if len(direction) > 0:
                if invertDirection == False:
                    filters.append(ADTrust.Direction.ilike("%"+direction+"%"))
                else:
                    filters.append(ADTrust.Direction.notilike("%"+direction+"%"))
            if len(domain) > 0:
                if invertDomain == False:
                    ids = [d.id for d in  ADDomain.query.filter(ADDomain.Name.ilike("%"+domain+"%")).all()]
                    filters.append(ADTrust.Domain_id.in_(ids))
                else:
                    ids = [d.id for d in  ADDomain.query.filter(ADDomain.Name.notilike("%"+domain+"%")).all()]
                    filters.append(ADTrust.Domain_id.in_(ids))
            if len(distinguishedName) > 0:
                if invertDistinguishedName == False:
                    filters.append(ADTrust.DistinguishedName.ilike("%"+distinguishedName+"%"))
                else:
                    filters.append(ADTrust.DistinguishedName.notilike("%"+distinguishedName+"%"))

            trusts = ADTrust.query.filter(and_(*filters)).all()

            if 'download' in request.form:
                output = generate_trust_excel(trust_list=trusts)
                return Response(output, mimetype="text/xslx",
                                headers={"Content-disposition": "attachment; filename=domain-trusts.xlsx",
                                         "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})

        else:
            return render_template('adtrust_search_list.html', form=form)
    else:
        trusts = ADTrust.query.all()

    return render_template('adtrust_search_list.html', form=form, trusts=trusts)


@ad_bp.route('/ad/trusts/<int:id>', methods=['GET'])
@login_required
def trust_detail(id):
    trust = ADTrust.query.get_or_404(id)
    return render_template('adtrust_details.html', trust=trust)
