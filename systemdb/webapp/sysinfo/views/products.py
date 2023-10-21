from flask import render_template, request, Response
from flask_login import login_required
from sqlalchemy import and_

from systemdb.webapp.sysinfo import sysinfo_bp
from systemdb.core.export.excel.products import generate_products_excel
from systemdb.webapp.sysinfo.forms.products import ProductSearchForm
from systemdb.core.models.sysinfo import Product
from systemdb.core.models.sysinfo import Host


@sysinfo_bp.route('/products/', methods=['GET'])
@login_required
def product_list():
    products = Product.query.all()
    return render_template('sysinfo/product/product_list.html', products=products)


@sysinfo_bp.route('/products/search/', methods=['GET', 'POST'])
@login_required
def product_search_list():
    form = ProductSearchForm()

    if request.method == 'POST':
        filters = []
        if form.validate_on_submit():
            caption = form.Caption.data
            name = form.Name.data
            version = form.Version.data
            host = form.Host.data
            installLocation = form.InstallLocation.data

            invertCaption = form.InvertCaption.data
            invertName = form.InvertName.data
            invertVersion = form.InvertVersion.data
            invertHost = form.InvertHost.data
            invertInstallLocation = form.InvertInstallLocation.data

            if len(caption) > 0 :
                if invertCaption == False:
                    filters.append(Product.Caption.ilike("%"+caption+"%"))
                else:
                    filters.append(Product.Caption.notilike("%"+caption+"%"))
            if len(name) > 0:
                if invertName == False:
                    filters.append(Product.Name.ilike("%"+name+"%"))
                else:
                    filters.append(Product.Name.notilike("%"+name+"%"))
            if len(version) > 0:
                if invertVersion == False:
                    filters.append(Product.Version.ilike("%"+version+"%"))
                else:
                    filters.append(Product.Version.notilike("%"+version+"%"))
            if len(host) > 0:
                if invertHost == False:
                    ids = [h.id for h in  Host.query.filter(Host.Hostname.ilike("%"+host+"%")).all()]
                    filters.append(Product.Host_id.in_(ids))
                else:
                    ids = [h.id for h in Host.query.filter(Host.Hostname.notilike("%" + host + "%")).all()]
                    filters.append(Product.Host_id.in_(ids))
            if len(installLocation) > 0:
                if invertInstallLocation == False:
                    filters.append(Product.InstallLocation.ilike("%"+installLocation+"%"))
                else:
                    filters.append(Product.InstallLocation.notilike("%"+installLocation+"%"))

            products = Product.query.filter(and_(*filters)).all()

            if 'download' in request.form:
                output = generate_products_excel(products=products)
                return Response(output, mimetype="text/xslx",
                                headers={"Content-disposition": "attachment; filename=products.xlsx",
                                         "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})
        else:
            return render_template('sysinfo/product/product_search_list.html', form=form)
    else:
        products = []

    return render_template('sysinfo/product/product_search_list.html', form=form, products=products)
