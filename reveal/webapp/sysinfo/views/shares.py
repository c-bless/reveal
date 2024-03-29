from flask import render_template, request, Response
from flask_login import login_required

from reveal.webapp.sysinfo import sysinfo_bp

from reveal.core.models.sysinfo import Host
from reveal.core.models.sysinfo import Share

from reveal.webapp.sysinfo.forms.shares import ShareSearchForm
from reveal.core.export.excel.shares import generate_shares_excel


@sysinfo_bp.route('/shares/<int:id>', methods=['GET'])
@login_required
def share_detail(id):
    share = Share.query.get_or_404(id)
    host = Host.query.get_or_404(share.Host_id)
    return render_template("sysinfo/share/share_details.html", share=share, host=host)


@sysinfo_bp.route('/shares/', methods=['GET', 'POST'])
@login_required
def share_search_list():
    form = ShareSearchForm()

    if request.method == 'POST':
        filters = []
        if form.validate_on_submit():
            name = form.Name.data
            host = form.Host.data
            pathname = form.Path.data
            description = form.Description.data
            invertName = form.InvertName.data
            invertDescription = form.InvertDescription.data
            invertPath = form.InvertPath.data
            invertHost = form.InvertHost.data
            hide_c_dollar = form.Hide_C_Dollar.data
            hide_d_dollar = form.Hide_D_Dollar.data
            hide_e_dollar = form.Hide_E_Dollar.data
            hide_f_dollar = form.Hide_F_Dollar.data
            hide_g_dollar = form.Hide_G_Dollar.data
            hide_ADMIN_dollar = form.Hide_ADMIN_Dollar.data
            hide_IPC_dollar = form.Hide_IPC_Dollar.data
            hide_PRINT_dollar = form.Hide_PRINT_Dollar.data

            if len(name) > 0:
                if invertName == False:
                    filters.append(Share.Name.ilike("%" + name + "%"))
                else:
                    filters.append(Share.Name.notilike("%" + name + "%"))
            if len(host) > 0:
                if invertHost == False:
                    filters.append(Share.Host.ilike("%" + host + "%"))
                else:
                    filters.append(Share.Host.notilike("%" + host + "%"))
            if len(description) > 0:
                if invertDescription == False:
                    filters.append(Share.Description.ilike("%" + description + "%"))
                else:
                    filters.append(Share.Description.notilike("%" + description + "%"))
            if len(pathname) > 0:
                if invertPath == False:
                    filters.append(Share.Path.ilike("%" + pathname + "%"))
                else:
                    filters.append(Share.Path.notilike("%" + pathname + "%"))
            if (hide_IPC_dollar):
                filters.append(Share.Name != "IPC$")
            if (hide_ADMIN_dollar):
                filters.append(Share.Name != "ADMIN$")
            if (hide_PRINT_dollar):
                filters.append(Share.Name != "print$")
            if (hide_c_dollar):
                filters.append(Share.Name != "C$")
            if (hide_d_dollar):
                filters.append(Share.Name != "D$")
            if (hide_e_dollar):
                filters.append(Share.Name != "E$")
            if (hide_f_dollar):
                filters.append(Share.Name != "F$")
            if (hide_g_dollar):
                filters.append(Share.Name != "G$")
            shares = Share.query.filter(*filters).all()
            if 'download' in request.form:
                output = generate_shares_excel(shares=shares)
                return Response(output, mimetype="text/xslx",
                                headers={"Content-disposition": "attachment; filename=shares.xlsx",
                                        "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})

        else:
            return render_template('sysinfo/share/share_search_list.html', form=form)
    else:
        shares = []

    return render_template('sysinfo/share/share_search_list.html', form=form, shares=shares)
