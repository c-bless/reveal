from flask import render_template

from ..models.activedirectory import ADComputer, ADDomainController, ADForestGlobalCatalog
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


@ad_bp.route('/ad/domain/<int:id>/computer', methods=['GET'])
def computer_by_domain_list(id):
    computer_list = ADComputer.query.filter(ADComputer.Domain_id==id)
    return render_template('adcomputer_list.html', computer_list=computer_list)

@ad_bp.route('/ad/computer/<int:id>', methods=['GET'])
def computer_detail(id):
    computer = ADComputer.query.get_or_404(id)
    return render_template('adcomputer_details.html', computer=computer)
