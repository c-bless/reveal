from flask import render_template

from ..core.ad_models import ADForest, ADForestGlobalCatalog, ADForestSite

from . import ad_bp
from flask import make_response


@ad_bp.route('/ad/forests', methods=['GET'])
def forest_list():
    forests = ADForest.query.all()
    return render_template('adforest_list.html', forests=forests)

@ad_bp.route('/ad/forest/<int:id>', methods=['GET'])
def forest_detail(id):
    forest = ADForest.query.get_or_404(id)
    site_list = ADForestSite.query.filter(ADForestSite.Forest_id == id).all()
    gc_list = ADForestGlobalCatalog.query.filter(ADForestGlobalCatalog.Forest_id == id).all()
    return render_template('adforest_details.html', forest=forest, site_list=site_list, gc_list=gc_list)
