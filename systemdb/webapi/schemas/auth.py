from apiflask import Schema
from apiflask.fields import String

class Token(Schema):
    token = String()
