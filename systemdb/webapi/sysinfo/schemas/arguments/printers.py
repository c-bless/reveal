from apiflask import Schema
from apiflask.fields import String
from apiflask.fields import List
from apiflask.validators import Regexp

from systemdb.core.regex import RE_SYSINFO_PRINTERNAME


class PrinterMatchSearchSchema(Schema):
    names = List(String(validate=Regexp(regex=RE_SYSINFO_PRINTERNAME)))
