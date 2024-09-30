import os
from flask import current_app

from io import BytesIO

import xlsxwriter
import yaml


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
                running = []
                not_running = []
                disabled = []
                for s in h.Services:
                    if s.Started is True:
                        running.append(s.Name)
                    else:
                        not_running.append(s.Name)
                    if s.StartMode not in ["Disabled", "Manual"]:
                        s.disabled = False
                if "running" in ssc and "names" in ssc["running"]:
                    for r in ssc["running"]["names"]:
                        if r not in running:
                            results.append([h.Hostname, h.SystemGroup, "service status checks (running) ", r, "Failed",
                                            f"Service ({r}) is not running"])
                        else:
                            results.append([h.Hostname, h.SystemGroup, "service status checks (running) ", r, "Pass",""])
                if "not_running" in ssc and "names" in ssc["running"]:
                    for r in ssc["not_running"]["names"]:
                        if r not in not_running:
                            results.append([h.Hostname, h.SystemGroup, "service status checks (not running)", r, "Failed",
                                 f"Service ({r}) is running"])
                        else:
                            results.append([h.Hostname, h.SystemGroup, "service status checks (not running) ", r, "Pass", ""])
                if "disabled" in ssc and "names" in ssc["disabled"]:
                    for r in ssc["disabled"]["names"]:
                        if r not in disabled:
                            results.append([h.Hostname, h.SystemGroup, "service status checks (disabled)", r, "Failed",
                                            f"Service ({r}) not disabled"])
                        else:
                            results.append([h.Hostname, h.SystemGroup, "service status checks (disabled) ", r, "Pass",""])
            if "firewall_checks" in checks["system"]:
                fwc = checks["system"]["firewall_checks"]
                if "enabled_profiles" in fwc:
                    profiles = ["public", "private", "domain"]
                    for p in profiles:
                        if p in fwc["enabled_profiles"]:
                            fw_result = True
                            if p == "public" and h.FwProfilePublic is False: fw_result = False
                            if p == "private" and h.FwProfilePrivate is False: fw_result = False
                            if p == "domain" and h.FwProfileDomain is False: fw_result = False
                            if fw_result is False:
                                results.append([h.Hostname, h.SystemGroup, "Firewall status check", p, "Failed",
                                                f"Firewall is disabled for profile ({p})"])
                            else:
                                results.append([h.Hostname, h.SystemGroup, "Firewall status check", p, "Pass", ""])
                if "disabled_profiles" in fwc:
                    profiles = ["public", "private", "domain"]
                    for p in profiles:
                        if p in fwc["disabled_profiles"]:
                            fw_result = True
                            if p == "public" and h.FwProfilePublic is True: fw_result = False
                            if p == "private" and h.FwProfilePrivate is True: fw_result = False
                            if p == "domain" and h.FwProfileDomain is True: fw_result = False
                            if fw_result is False:
                                results.append([h.Hostname, h.SystemGroup, "Firewall status check", p, "Failed",
                                                f"Firewall is enabled for profile ({p})"])
                            else:
                                results.append([h.Hostname, h.SystemGroup, "Firewall status check", p, "Pass", ""])
            if "SMB" in checks["system"]:
                smb = checks["system"]["SMB"]
                if "v1" in smb:
                    if smb["v1"] != h.SMBv1Enabled:
                        if h.SMBv1Enabled is True:
                            results.append([h.Hostname, h.SystemGroup, "SMBv1 enabled check", "SMBv1", "Failed",
                                            f"SMBv1 was expected to be disabled"])
                        else:
                            results.append([h.Hostname, h.SystemGroup, "SMBv1 enabled check", "SMBv1", "Failed",
                                            f"SMBv1 was expected to be enabled"])
                    else:
                        results.append([h.Hostname, h.SystemGroup, "SMBv1 enabled check", "SMBv1", "Pass", ""])
                if "signing_enabled" in smb:
                    if smb["signing_enabled"] != h.SMBEnableSecuritySignature:
                        if h.SMBEnableSecuritySignature is True:
                            results.append([h.Hostname, h.SystemGroup, "SMBv1 signing enabled check", "SMBv1", "Failed",
                                            f"SMBv1 signing was expected to be disabled"])
                        else:
                            results.append([h.Hostname, h.SystemGroup, "SMBv1 signing enabled check", "SMBv1", "Failed",
                                            f"SMBv1 signing was expected to be enabled"])
                    else:
                        results.append([h.Hostname, h.SystemGroup, "SMBv1 signing enabled check", "SMBv1", "Pass", ""])
                if "signing_required" in smb:
                    if smb["signing_required"] != h.SMBRequireSecuritySignature:
                        if h.SMBRequireSecuritySignature is True:
                            results.append([h.Hostname, h.SystemGroup, "SMBv1 signing required check", "SMBv1",
                                            "Failed", f"SMBv1 signing was not expected to be required (optional)"])
                        else:
                            results.append([h.Hostname, h.SystemGroup, "SMBv1 signing required check", "SMBv1",
                                            "Failed", f"SMBv1 signing was expected to be required"])
                    else:
                        results.append([h.Hostname, h.SystemGroup, "SMBv1 signing required check", "SMBv1", "Pass", ""])
            if "WSUS" in checks["system"]:
                if "https_enabled" in checks["system"]["WSUS"]:
                    https_enabled = checks["system"]["WSUS"]["https_enabled"]
                    server = h.WUServer
                    if not server.startswith("https://"):
                        results.append([h.Hostname, h.SystemGroup, "WSUS via http", server, "Failed",
                                        "WSUS is not configured for https"])
                    else:
                        results.append([h.Hostname, h.SystemGroup, "WSUS via http", server, "Pass", ""])
        result_class.results.extend(results)
    return result_class


def generate_configreview_excel(results=[]):
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
    for res in results:
        for c in res:
            worksheet.write(row, col, str(c))
            col += 1
        col = 0
        row += 1

    worksheet.autofilter("A1:F1")
    worksheet.autofit()
    # Close the workbook before streaming the data.
    workbook.close()

    # Rewind the buffer.
    output.seek(0)
    return output
