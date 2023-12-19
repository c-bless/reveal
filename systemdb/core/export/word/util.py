import os
from flask import current_app


def get_host_report_directory()->str:
    return "{0}/templates/reports/HostReports/".format(current_app.config.get(('REPORT_DIR')))

def get_host_report_templates()-> list[str]:
    template_dir = get_host_report_directory()
    return os.listdir(template_dir)