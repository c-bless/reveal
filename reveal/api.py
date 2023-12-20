from reveal.config import ApiConfig
from reveal.webapi import create_app


config = ApiConfig()

app = create_app(config)

