
class ComplianceResult(object):
    compliant: str
    messages: list[str]

    def __init__(self, compliant=False):
        super.__init__(self)
        self.compliant = compliant
        self.messages = []
