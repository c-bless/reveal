from reveal.config import AppConfig
from reveal.webapp import create_app


config = AppConfig()

app = create_app(config)

