#!/usr/bin/env python

from flask_script import Manager
from flask_script.commands import Server, ShowUrls

from app import create_app, db
from app.core.commands import InitDB, ImportCommand
from config import Config

config = Config()
app = create_app(config)

manager = Manager(app)
manager.add_command("runserver", Server(use_reloader=True))
manager.add_command("show_urls", ShowUrls())

manager.add_command('init', InitDB())
manager.add_command('import', ImportCommand())

with app.app_context():
    db.metadata.create_all(bind=db.engine)

if __name__ == "__main__":
    manager.run()