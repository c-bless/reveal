from apiflask import Schema
from apiflask.fields import String
from apiflask.fields import Nested

from systemdb.webapi.sysinfo.schemas.responses.hosts import HostNestedSchema


class PrinterMatchSchema(Schema):

    Printer = String(allow_none=False)
    Hosts = Nested(HostNestedSchema, many=True, allow_none=True)
