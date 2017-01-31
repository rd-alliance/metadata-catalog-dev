#! /usr/bin/python3

### Dependencies

## Standard


## Non-standard

# See http://flask.pocoo.org/docs/0.12/
# On Debian, Ubuntu, etc.: sudo apt-get install python3-flask
from flask import Flask

# See http://tinydb.readthedocs.io/en/latest/intro.html
# Install from PyPi: pip install tinydb
from tinydb import TinyDB, Query

### Basic setup

app = Flask (__name__)
