from sqlalchemy import and_

from reveal.core.models.sysinfo import Host
from reveal.core.models.eol import EoL
from reveal.webapi.sysinfo.schemas.responses.eol import EoLMatchSchema


def get_EoLInfo(host_filter=[]):
    eols = EoL.query.filter(EoL.EndOfService == True).all()
    eol_matches = []
    special_os_versions = ["Pro", "LTSC", "LTSB"]
    for e in eols:
        eol_match = EoLMatchSchema()
        eol_match.Eol = e
        in_list = False
        for v in special_os_versions:
            if v in e.OS:
                in_list = True
                hosts = Host.query.filter(and_((Host.OSBuildNumber.ilike(e.Build +"%")),
                                               (Host.OSName.ilike(f'%{v}%'))
                                               )).all()
                eol_match.Hosts = hosts
        if not in_list:
            conditions = []
            for v in special_os_versions:
                conditions.append(Host.OSName.notilike(f'%{v}%'))
            hosts = Host.query.filter(and_((Host.OSBuildNumber == e.Build), *conditions, *host_filter)).all()
            eol_match.Hosts = hosts

        eol_matches.append(eol_match)
    return eol_matches