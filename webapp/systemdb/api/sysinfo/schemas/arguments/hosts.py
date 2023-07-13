from ....ma import ma
from marshmallow.validate import Regexp
from marshmallow import fields


class HostnameSearchSchema(ma.Schema):
    hostname = fields.String(required=True, validate=Regexp(regex="^([a-zA-Z0-9 \.\-\_]+)?$"))


class IPSearchSchema(ma.Schema):
    IP = fields.IP(required=True)

