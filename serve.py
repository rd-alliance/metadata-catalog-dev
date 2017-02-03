#! /usr/bin/python3

### Dependencies

## Standard

import os, sys

## Non-standard

# See http://flask.pocoo.org/docs/0.12/
# On Debian, Ubuntu, etc.:
#   - old version: sudo apt-get install python3-flask
#   - latest version: sudo pip3 install flask
from flask import Flask, request, url_for, render_template, g

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
    return render_template('home.html')

### Display metadata scheme

@app.route('/msc/m<int:number>')
def scheme(number):
    schemes = db.table('metadata-schemes')
    element = schemes.get(eid=number)
    # Here we interpret the meaning of the versions
    versions = None
    if 'versions' in element:
        versions = list()
        raw_versions = element['versions']
        for v in raw_versions:
            this_version = dict()
            if not 'number' in v:
                continue
            this_version['number'] = v['number']
            this_version['status'] = ''
            if 'issued' in v:
                this_version['date'] = v['issued']
                if 'valid' in v:
                    if '/' in v['valid']:
                        date_range = v['valid'].partition('/')
                        this_version['status'] = 'deprecated on '.format(date_range[2])
                    else:
                        this_version['status'] = 'current'
            elif 'valid' in v:
                if '/' in v['valid']:
                    date_range = v['valid'].partition('/')
                    this_version['date'] = date_range[0]
                    this_version['status'] = 'deprecated on '.format(date_range[2])
                else:
                    this_version['date'] = v['valid']
                    this_version['status'] = 'current'
            elif 'available' in v:
                this_version['date'] = v['available']
                this_version['status'] = 'proposed'
            versions.append(this_version)
        versions = sorted(versions, key=lambda k: k['date'], reverse=True)
        for version in versions:
            if version['status'] == 'current':
                break
            if version['status'] == 'proposed':
                continue
            if version['status'] == '':
                version['status'] = 'current'
                break
    return render_template('metadata-scheme.html', record=element,\
        versions=versions)

### Search form

@app.route('/search', methods=['GET', 'POST'])
def search():
    if request.method == 'POST':
        pass
    else:
        pass

### Executing

if __name__ == '__main__':
    app.run(debug=True)
