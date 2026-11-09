from apiflask import Schema
from apiflask.fields import String, List, Integer
from apiflask.validators import Regexp, Length
from marshmallow import validates_schema, ValidationError

from reveal.core.hosts import HOST_ASSIGNMENT_FIELDS
from reveal.core.regex import RE_SYSINFO_HOSTNAME
from reveal.core.regex import RE_SYSINFO_SYSTEMGROUP
from reveal.core.regex import RE_SYSINFO_LOCATION
from reveal.core.regex import RE_SYSINFO_LABEL


class HostByNameSearchSchema(Schema):
    name = String(required=True, validate=Regexp(regex=RE_SYSINFO_HOSTNAME))

class HostByIPSearchSchema(Schema):
    ip = String(required=True)


# maximum number of hosts that can be updated with one request
MAX_BULK_HOSTS = 1000


class HostAssignmentSchema(Schema):
    """
    Update of the assignment of a host. Only the fields contained in the request are changed. null or an empty
    string removes the value.
    """
    SystemGroup = String(allow_none=True, validate=[Length(max=256), Regexp(regex=RE_SYSINFO_SYSTEMGROUP)],
                         metadata={"description": "System group of the host (e.g. PCS7)"})
    Location = String(allow_none=True, validate=[Length(max=256), Regexp(regex=RE_SYSINFO_LOCATION)],
                      metadata={"description": "Location of the host (e.g. Control room)"})
    Label = String(allow_none=True, validate=[Length(max=256), Regexp(regex=RE_SYSINFO_LABEL)],
                   metadata={"description": "Additional label (e.g. inventory number)"})

    @validates_schema
    def validate_fields(self, data, **kwargs):
        if not any(f in data for f in HOST_ASSIGNMENT_FIELDS):
            raise ValidationError("At least one of SystemGroup, Location or Label is required.")


class HostBulkAssignmentSchema(HostAssignmentSchema):
    """
    Update of the assignment of several hosts. The hosts are selected either by their IDs or by their hostnames.
    """
    host_ids = List(Integer(), validate=Length(min=1, max=MAX_BULK_HOSTS),
                    metadata={"description": "IDs of the hosts to update"})
    hostnames = List(String(validate=[Length(min=1, max=256), Regexp(regex=RE_SYSINFO_HOSTNAME)]),
                     validate=Length(min=1, max=MAX_BULK_HOSTS),
                     metadata={"description": "Hostnames of the hosts to update (all hosts with this hostname)"})

    @validates_schema
    def validate_selection(self, data, **kwargs):
        if ("host_ids" in data) == ("hostnames" in data):
            raise ValidationError("Exactly one of host_ids or hostnames is required.")
