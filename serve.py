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
from tinydb import TinyDB, Query, where

### Basic setup

app = Flask (__name__)
app.jinja_env.trim_blocks = True
app.jinja_env.lstrip_blocks = True

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

    # Here we assemble information about related entities
    organizations = db.table('organizations')
    endorsements = db.table('endorsements')
    tools = db.table('tools')
    mappings = db.table('mappings')
    relations = dict()
    endorsement_ids = list()
    hasRelatedSchemes = False
    if 'relatedEntities' in element:
        for entity in element['relatedEntities']:
            if entity['role'] == 'parent scheme':
                if not 'parents' in relations:
                    relations['parents'] = list()
                entity_number = int(entity['id'][5:])
                element_record = schemes.get(eid=entity_number)
                if element_record:
                    relations['parents'].append(element_record)
                    hasRelatedSchemes = True

            elif entity['role'] == 'maintainer':
                if not 'maintainers' in relations:
                    relations['maintainers'] = list()
                entity_number = int(entity['id'][5:])
                element_record = organizations.get(eid=entity_number)
                if element_record:
                    relations['maintainers'].append(element_record)

            elif entity['role'] == 'funder':
                if not 'funders' in relations:
                    relations['funders'] = list()
                entity_number = int(entity['id'][5:])
                element_record = organizations.get(eid=entity_number)
                if element_record:
                    relations['funders'].append(element_record)

            elif entity['role'] == 'user':
                if not 'users' in relations:
                    relations['users'] = list()
                entity_number = int(entity['id'][5:])
                element_record = organizations.get(eid=entity_number)
                if element_record:
                    relations['users'].append(element_record)

            elif entity['role'] == 'endorsement':
                if not entity['id'] in endorsement_ids:
                    endorsement_ids.append(entity['id'])

    Endorsement = Query()
    related_endorsements = endorsements.search(Endorsement.relatedEntities.any(where('id') == 'msc:m{}'.format(number)))
    for entity in related_endorsements:
        entity_id = 'msc:e{}'.format(entity.eid)
        if not entity_id in endorsement_ids:
            endorsement_ids.append(entity_id)
    if len(endorsement_ids) > 0:
        relations['endorsements'] = list()
        for endorsement_id in endorsement_ids:
            entity_number = int(endorsement_id['id'][5:])
            element_record = endorsements.get(eid=entity_number)
            if element_record:
                if 'relatedEntities' in element_record:
                    for entity in element_record['relatedEntities']:
                        if entity['role'] == 'originator':
                            org_entity_number = int(entity['id'][5:])
                            org_record = organizations.get(eid=org_entity_number)
                            element_record['originator'] = org_record['name']
                if 'valid' in element_record:
                    if '/' in element_record['valid']:
                        date_range = element_record['valid'].partition('/')
                        element_record['valid from'] = date_range[0]
                        element_record['valid until'] = date_range[2]
                    else:
                        element_record['valid from'] = element_record['valid']
                relations['endorsements'].append(element_record)

    Scheme = Query()
    # This optimization relies on schemes only pointing to parent schemes
    child_schemes = schemes.search(Scheme.relatedEntities.any(where('id') == 'msc:m{}'.format(number)))
    if len(child_schemes) > 0:
        relations['children'] = child_schemes
        hasRelatedSchemes = True

    Tool = Query()
    related_tools = tools.search(Tool.relatedEntities.any(where('id') == 'msc:m{}'.format(number)))
    if len(related_tools) > 0:
        relations['tools'] = related_tools

    Mapping = Query()
    related_mappings = mappings.search(Mapping.relatedEntities.any(where('id') == 'msc:m{}'.format(number)))
    mappings_from = list()
    mappings_to = list()
    for related_mapping in related_mappings:
        # This assumes the mapping has one input and one output, one of which is
        # the current scheme, and the other is a different scheme.
        for relation in related_mapping['relatedEntities']:
            if relation['id'] != 'msc:m{}'.format(number):
                if relation['role'] == 'input scheme':
                    entity_number = int(relation['id'][5:])
                    related_mapping['input scheme'] = schemes.get(eid=entity_number)
                elif relation['role'] == 'output scheme':
                    entity_number = int(relation['id'][5:])
                    related_mapping['output scheme'] = schemes.get(eid=entity_number)
        if 'output scheme' in related_mapping:
            mappings_from.append(related_mapping)
        elif 'input scheme' in related_mapping:
            mappings_to.append(related_mapping)
    if len(mappings_from) > 0:
        relations['mappings from'] = mappings_from
        hasRelatedSchemes = True
    if len(mappings_to) > 0:
        relations['mappings to'] = mappings_to
        hasRelatedSchemes = True
    return render_template('metadata-scheme.html', record=element,\
        versions=versions, relations=relations, hasRelatedSchemes=hasRelatedSchemes)

### Display tool

@app.route('/msc/t<int:number>')
def tool(number):
    pass

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
