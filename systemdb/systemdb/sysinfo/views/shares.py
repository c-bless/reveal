from flask import render_template
from flask_login import login_required

from .. import sysinfo_bp

from ...models.sysinfo import Host, Share


@sysinfo_bp.route('/shares/<int:id>', methods=['GET'])
@login_required
def share_detail(id):
    share = Share.query.get_or_404(id)
    host = Host.query.get_or_404(share.Host_id)
    ntfs_permissions = share.NTFSPermission.split("\n") if share.NTFSPermission is not None else ""
    share_permissions = share.SharePermission.split("\n") if share.SharePermission is not None else ""
    return render_template("share_details.html", share=share, host=host, ntfs_permissions=ntfs_permissions, share_permissions=share_permissions)
