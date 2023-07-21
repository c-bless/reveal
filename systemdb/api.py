from systemdb.config import ApiConfig
from systemdb.webapi import create_app


config = ApiConfig()

app = create_app(config)

