# coding: utf-8

"""This module defines some basic commands that can be used by manage.py"""

from flask_script import Command, Option

from .db import db


class InitDB(Command):
    def run(self):
        db.session.commit()


class ImportCommand(Command):

    option_list = (
        Option('--file', '-f', dest='filename'),
        Option('--dir', '-d', dest='directory'),
    )

    def run(self, filename=None, directory=None):
        pass
