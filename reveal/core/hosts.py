"""
Functions to change hosts. Used by the web application and the REST API.
"""
from flask import current_app

from reveal.core.models.sysinfo import Host

# fields of a host that describe its assignment (system group, location, label)
HOST_ASSIGNMENT_FIELDS = ("SystemGroup", "Location", "Label")


def apply_host_assignment(host: Host, data: dict, changed_by: str) -> dict:
    """
    Sets the assignment fields (SystemGroup, Location, Label) contained in data on the host. Fields that are not
    contained in data are not changed. Empty strings and None remove the value. The changes are written to the
    application log (who, which host, old -> new value). The changes are not committed.

    :param host: host to change
    :param data: dictionary with the new values (keys: SystemGroup, Location, Label)
    :param changed_by: name of the user that changes the host (for the log)
    :return: dictionary of the changed fields: {field: (old value, new value)}
    """
    changes = {}
    for field in HOST_ASSIGNMENT_FIELDS:
        if field in data:
            new_value = data[field] or None
            old_value = getattr(host, field)
            if old_value != new_value:
                setattr(host, field, new_value)
                changes[field] = (old_value, new_value)
    if changes:
        current_app.logger.info("Host assignment changed by %s: host id=%s hostname=%s %s",
                                changed_by, host.id, host.Hostname, changes)
    return changes


def get_assignment_values() -> dict:
    """
    Returns the values that are currently used for SystemGroup, Location and Label (sorted, without empty values),
    e.g. as suggestions in input fields.

    :return: {field: [values]}
    """
    result = {}
    for field in HOST_ASSIGNMENT_FIELDS:
        column = getattr(Host, field)
        rows = Host.query.with_entities(column).filter(column.isnot(None), column != "").distinct().all()
        result[field] = sorted((r[0] for r in rows), key=str.lower)
    return result
