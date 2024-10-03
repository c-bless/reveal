import os
from flask import current_app

from io import BytesIO

import xlsxwriter
import yaml

from reveal.core.configreview.checks.servicechecks import verify_services_running
from reveal.core.configreview.checks.servicechecks import verfiy_services_disabled
from reveal.core.configreview.checks.servicechecks import verify_services_not_running

from reveal.core.configreview.checks.hardeningchecks import verify_wsus_https
from reveal.core.configreview.checks.hardeningchecks import verify_smb_signing_enabled
from reveal.core.configreview.checks.hardeningchecks import verify_smb_signing_disabled
from reveal.core.configreview.checks.hardeningchecks import verify_smbv1_disabled
from reveal.core.configreview.checks.hardeningchecks import verify_smbv1_enabled
from reveal.core.configreview.checks.hardeningchecks import verify_smb_signing_required
from reveal.core.configreview.checks.hardeningchecks import verify_smb_signing_not_required
from reveal.core.configreview.checks.hardeningchecks import verify_firewall_enabled
from reveal.core.configreview.checks.hardeningchecks import verify_firewall_disabled
from reveal.core.configreview.checks.hardeningchecks import verify_configchecks

from reveal.core.configreview import ConfigReviewResult

class ConfigReviewResults(object):

    name = ""
    version = ""
    description = ""
    reference = ""
    results = []

    def __init__(self):
        super().__init__()


def get_configreview_checks_directory()->str:
    return "{0}/".format(current_app.config.get(('CONFIGREVIEW_DIR')))


def get_configreview_checks()-> list[str]:
    template_dir = get_configreview_checks_directory()
    return os.listdir(template_dir)


def load_configreview_checks(fname):
    check_dir = get_configreview_checks_directory()
    if fname in os.listdir(check_dir):
        with open(f"{check_dir}/{fname}") as f:
            checks = yaml.safe_load(f)
        return checks
    return None


def verify_config_checks(hosts, checks):
    result_class = ConfigReviewResults()
    if "meta" in checks:
        meta = checks['meta']
        if "name" in meta: result_class.name = meta['name']
        if "version" in meta: result_class.version = meta['version']
        if "description" in meta: result_class.description = meta['description']
        if "reference" in meta: result_class.reference = meta['reference']
    for h in hosts:
        results = []
        if "system" in checks:
            if "service_status_checks" in checks["system"]:
                ssc = checks["system"]["service_status_checks"]
                if "running" in ssc and "names" in ssc["running"]:
                    names = ssc["running"]["names"]
                    results.extend(verify_services_running(h, names))
                if "not_running" in ssc and "names" in ssc["running"]:
                    names = ssc["not_running"]["names"]
                    results.extend(verify_services_not_running(h, names))
            if "service_startmode_checks" in checks["system"]:
                ssc = checks["system"]["service_startmode_checks"]
                if "disabled" in ssc and "names" in ssc["disabled"]:
                    names = ssc["disabled"]["names"]
                    results.extend(verfiy_services_disabled(h, names))
            if "firewall_checks" in checks["system"]:
                fwc = checks["system"]["firewall_checks"]
                if "enabled_profiles" in fwc:
                    results.extend(verify_firewall_enabled(h, fwc["enabled_profiles"]))
                if "disabled_profiles" in fwc:
                    results.extend(verify_firewall_disabled(h, fwc["disabled_profiles"]))
            if "SMB" in checks["system"]:
                smb = checks["system"]["SMB"]
                if "v1_enabled" in smb:
                    if smb["v1_enabled"] is False:
                        results.append(verify_smbv1_disabled(h))
                    else:
                        results.append(verify_smbv1_enabled(h))
                if "signing_enabled" in smb:
                    if smb["signing_enabled"] is False:
                        results.append(verify_smb_signing_disabled(h))
                    else:
                        results.append(verify_smb_signing_enabled(h))
                if "signing_required" in smb:
                    if smb["signing_required"] is False:
                        results.append(verify_smb_signing_not_required(h))
                    else:
                        results.append(verify_smb_signing_required(h))
            if "WSUS" in checks["system"]:
                if "https_enabled" in checks["system"]["WSUS"]:
                    https_enabled = checks["system"]["WSUS"]["https_enabled"]
                    if https_enabled is True:
                        results.append(verify_wsus_https(h))
            if "configcheck_results" in checks["system"]:
                cc_checks = checks["system"]["configcheck_results"]
                results.extend(verify_configchecks(h, cc_checks))
        result_class.results.extend(results)
    return result_class


def generate_configreview_excel(result: ConfigReviewResults):
    output = BytesIO()
    workbook = xlsxwriter.Workbook(output, {"in_memory": True})
    worksheet = workbook.add_worksheet()

    header_data = ["Hostname", "Systemgroup", "Check", "Component", "Result", "Message"]

    wrap_format = workbook.add_format({'text_wrap': True})
    header_format = workbook.add_format({'bold': True,
                                         'bottom': 2,
                                         'bg_color': '#CCCCCC'})

    for col_num, data in enumerate(header_data):
        worksheet.write(0, col_num, data, header_format)

    # Start from the first cell. Rows and columns are zero indexed.
    row = 1
    col = 0
    # Iterate over the data and write it out row by row.
    for res in result.results:
        worksheet.write(row, 0, res.hostname)
        worksheet.write(row, 1, res.systemgroup)
        worksheet.write(row, 2, res.check)
        worksheet.write(row, 3, res.component)
        if res.compliant is True:
            worksheet.write(row, 4, "Pass")
        else:
            worksheet.write(row, 4, "Failed")
        worksheet.write(row, 5, res.message)
        row += 1

    worksheet.autofilter("A1:F1")
    worksheet.autofit()
    # Close the workbook before streaming the data.
    workbook.close()

    # Rewind the buffer.
    output.seek(0)
    return output
