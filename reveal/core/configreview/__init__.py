
class ComplianceResult(object):
    compliant: str
    messages: list[str]


    def __init__(self, compliant=False):
        super.__init__(self)
        self.compliant = compliant
        self.messages = []


class ConfigReviewResult(object):
    hostname: str
    systemgroup: str
    compliant: bool
    check: str
    component: str
    message: str

    def __init__(self, compliant=False, check="", component="", message="", hostname="", systemgroup=""):
        super().__init__()
        self.compliant = compliant
        self.check = check
        self.component = component
        self.message = message
        self.hostname = hostname
        self.systemgroup = systemgroup

    def __str__(self):
        s = f"host: {self.hostname}, check: {self.check}"
        return s

