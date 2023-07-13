#!/usr/bin/env python

from webapp.config import Config
from webapp.systemdb import create_app


config = Config()

app = create_app(config)

