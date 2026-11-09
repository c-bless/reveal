from sqlalchemy import and_

from reveal.core.models.sysinfo import Host
from reveal.core.models.eol import EoL
from reveal.webapi.sysinfo.schemas.responses.eol import EoLMatchSchema


def get_EoLInfo(host_filter=[]):
    eols = EoL.query.filter(EoL.EndOfService == True).all()
    eol_matches = []
    special_os_versions = ["Pro", "Server 2000", "Server 2003", "Server 2008", "Server 2012", "Server 2016",
                           "Server 2019", "Server 2022", "LTSC", "LTSB"]
    # Load the hosts once (instead of one query per EoL entry) and match them in Python with the same conditions as
    # the former SQL queries: ILIKE is case-insensitive, NULL values never match.
    # Note: as before, host_filter is only applied to the non-special OS versions.
    all_hosts = Host.query.order_by(Host.id).all()
    filtered_ids = {h.id for h in Host.query.filter(and_(*host_filter)).all()} if host_filter else None

    def lower(value):
        return value.lower() if value is not None else None

    for e in eols:
        eol_match = EoLMatchSchema()
        eol_match.Eol = e
        in_list = False
        build = lower(e.Build) or ""
        for v in special_os_versions:
            if v in e.OS:
                in_list = True
                # Host.OSBuildNumber ILIKE '<build>%' AND Host.OSName ILIKE '%<v>%'
                eol_match.Hosts = [h for h in all_hosts
                                   if lower(h.OSBuildNumber) is not None and lower(h.OSBuildNumber).startswith(build)
                                   and lower(h.OSName) is not None and v.lower() in lower(h.OSName)]
        if not in_list:
            # Host.OSBuildNumber == <build> AND Host.OSName NOT ILIKE '%<v>%' (all special versions) AND host_filter
            eol_match.Hosts = [h for h in all_hosts
                               if h.OSBuildNumber == e.Build
                               and lower(h.OSName) is not None
                               and not any(v.lower() in lower(h.OSName) for v in special_os_versions)
                               and (filtered_ids is None or h.id in filtered_ids)]

        eol_matches.append(eol_match)
    return eol_matches