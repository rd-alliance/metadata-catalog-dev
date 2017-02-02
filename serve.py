#! /usr/bin/python3

### Dependencies

## Standard

import os, sys

## Non-standard

# See http://flask.pocoo.org/docs/0.12/
# On Debian, Ubuntu, etc.:
#   - old version: sudo apt-get install python3-flask
#   - latest version: sudo pip3 install flask
from flask import Flask, request, url_for

# See http://tinydb.readthedocs.io/en/latest/intro.html
# Install from PyPi: sudo pip3 install tinydb
from tinydb import TinyDB, Query

### Basic setup

app = Flask (__name__)

script_dir = os.path.dirname(sys.argv[0])
db = TinyDB(os.path.realpath(os.path.join(script_dir, 'db.json')))

### Front page

@app.route('/')
def hello():
    page = '<html><head>'
    page += '<title>Testing</title>'
    style_url = url_for('static', filename='style.css')
    page += '<link rel="stylesheet" type="text/css" href="{}" />'.format(style_url)
    page += '</head><body><h1>Metadata Standards Catalog</h1></body></html>'
    return page

### Display metadata scheme

@app.route('/msc/m<int:number>')
def scheme(number):
    schemes = db.table('metadata-schemes')
    element = schemes.get(eid=number)
    return '<html><head><title>Testing</title></head><body><h1>{}</h1></body></html>'.format(\
        element['title'])

### Search form

@app.route('/search', methods=['GET', 'POST'])
def search():
    if request.method == 'POST':
        pass
    else:
        pass

### Executing

if __name__ == '__main__':
    app.run()
