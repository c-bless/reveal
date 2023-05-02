


class ReportProduct(object):

    def __init__(self, caption="", installDate="", description="", vendor="", name="", version="", installLocation=""):
        super().__init__()
        self._caption = caption
        self._installDate = installDate
        self._description = description
        self._vendor = vendor
        self._name = name
        self._version = version
        self._installLocation = installLocation

    @property
    def caption(self):
        return self._caption

    @property.setter
    def caption(self, value):
        self._caption = value

    @property
    def installDate(self):
        return self._installDate

    @property.setter
    def installDate(self, value):
        self._installDate = value

    @property
    def description(self):
        return self._description

    @property.setter
    def description(self, value):
        self._description = value


    @property
    def vendor(self):
        return self._vendor

    @property.setter
    def vendor(self, value):
        self._vendor = value


    @property
    def name(self):
        return self._name

    @property.setter
    def name(self, value):
        self._name = value


    @property
    def version(self):
        return self._version

    @property.setter
    def version(self, value):
        self._version = value


    @property
    def installLocation(self):
        return self._installLocation

    @property.setter
    def installLocation(self, value):
        self._installLocation = value

class ReportShare(object):

    def __init__(self, name="", path="", description="", NTFSPermission="", SharePermission=""):
        super().__init__()
        self._name = name
        self._path = path
        self._description = description
        self._NTFSPermission = NTFSPermission
        self._SharePermission = SharePermission


    @property
    def name(self):
        return self._name

    @property.setter
    def name(self, value):
        self._name = value


    @property
    def path(self):
        return self._path

    @property.setter
    def path(self, value):
        self._path = value


    @property
    def NTFSPermission(self):
        return self._NTFSPermission

    @property.setter
    def NTFSPermission(self, value):
        self._NTFSPermission = value


    @property
    def description(self):
        return self._description

    @property.setter
    def description(self, value):
        self._description = value



    @property
    def SharePermission(self):
        return self._SharePermission

    @property.setter
    def SharePermission(self, value):
        self._SharePermission = value


class ReportGroupMember(object):

    def __int__(self, name="", caption="", domain="", SID="", accountType=""):
        super().__init__()
        self._name = name
        self._caption = caption
        self._domain = domain
        self._SID = SID
        self._accountType = accountType

    @property
    def name(self):
        return self._name

    @property.setter
    def name(self, value):
        self._name = value


    @property
    def caption(self):
        return self._caption

    @property.setter
    def caption(self, value):
        self._caption = value


    @property
    def domain(self):
        return self._domain

    @property.setter
    def domain(self, value):
        self._domain= value


    @property
    def SID(self):
        return self._SID

    @property.setter
    def SID(self, value):
        self._SID = value

    @property
    def accountType(self):
        return self._accountType

    @property.setter
    def accountType(self, value):
        self._accountType = value



class ReportGroup(object):

    def __int__(self, name="", caption="", domain="", SID="", localAccount=""):
        super().__init__()
        self._name = name
        self._caption = caption
        self._domain = domain
        self._SID = SID
        self._localAccount = localAccount

    @property
    def name(self):
        return self._name

    @property.setter
    def name(self, value):
        self._name = value


    @property
    def caption(self):
        return self._caption

    @property.setter
    def caption(self, value):
        self._caption = value


    @property
    def domain(self):
        return self._domain

    @property.setter
    def domain(self, value):
        self._domain= value


    @property
    def SID(self):
        return self._SID

    @property.setter
    def SID(self, value):
        self._SID = value

    @property
    def localAccount(self):
        return self._localAccount

    @property.setter
    def localAccount(self, value):
        self._localAccount = value

