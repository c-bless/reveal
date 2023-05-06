from flask import render_template

from ..core.model import ADDomain, ADForest, ADTrust, ADUser, ADGroup, ADComputer, ADDomainController, ADForestGlobalCatalog, ADForestSite

from . import ad_bp

@ad_bp.route('/ad/dclist', methods=['GET'])
def dc_list():
    dc_list = ADDomainController.query.all()
    return render_template('addc_list.html', dc_list=dc_list)


@ad_bp.route('/ad/gclist', methods=['GET'])
def gc_list():
    gc_list = ADForestGlobalCatalog.query.all()
    return render_template('adgc_list.html', gc_list=gc_list)


@ad_bp.route('/ad/computer', methods=['GET'])
def computer_list():
    computer_list = ADComputer.query.all()
    return render_template('adcomputer_list.html', computer_list=computer_list)
