#!/usr/bin/env python

from .config import Config
from .systemdb import create_app
config = Config()

app = create_app(config)

