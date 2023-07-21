from systemdb.config import AppConfig
from systemdb.webapp import create_app


config = AppConfig()

app = create_app(config)

