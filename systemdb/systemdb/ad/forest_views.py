from flask import render_template
from flask_login import login_required

from ..models.activedirectory import ADForest, ADForestGlobalCatalog, ADForestSite

from . import ad_bp
from flask import make_response


@ad_bp.route('/ad/forests', methods=['GET'])
@login_required
def forest_list():
    forests = ADForest.query.all()
    return render_template('adforest_list.html', forests=forests)

@ad_bp.route('/ad/forest/<int:id>', methods=['GET'])
@login_required
def forest_detail(id):
    forest = ADForest.query.get_or_404(id)
    site_list = ADForestSite.query.filter(ADForestSite.Forest_id == id).all()
    gc_list = ADForestGlobalCatalog.query.filter(ADForestGlobalCatalog.Forest_id == id).all()
    return render_template('adforest_details.html', forest=forest, site_list=site_list, gc_list=gc_list)
