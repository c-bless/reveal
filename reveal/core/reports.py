
class ReportInfo(object):

    _name =""
    _category =""
    _tags = []
    _description = ""
    _views = []

    def __init__(self):
        super().__init__()

    def initWithParams(self, name="", category="", tags=[], description="", views=[]):
        super().__init__()
        self._name = name
        self._category = category
        self._tags = tags
        self._description = description
        self._views = views

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self,name=""):
        self._name = name

    @property
    def category(self):
        return self._category

    @category.setter
    def category(self, category=""):
        self._category = category

    @property
    def tags(self):
        return self._tags

    @tags.setter
    def tags(self, tags=[]):
        self._tags = tags

    @property
    def description(self):
        return self._description

    @description.setter
    def description(self, description=""):
        self._description = description

    @property
    def views(self):
        return self._views

    @views.setter
    def views(self, views= []):
        self._views = views

    def __str__(self):
        return str(self._name)
