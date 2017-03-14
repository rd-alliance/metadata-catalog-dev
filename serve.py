#! /usr/bin/python3

### Dependencies

## Standard

import os, sys, re, urllib, json, unicodedata

## Non-standard

# See http://flask.pocoo.org/docs/0.10/
# On Debian, Ubuntu, etc.:
#   - old version: sudo apt-get install python3-flask
#   - latest version: sudo -H pip3 install flask
from flask import Flask, request, url_for, render_template, flash, redirect, abort, jsonify, g, session

# See https://pythonhosted.org/Flask-OpenID/
# Install from PyPi: sudo -H pip3 install Flask-OpenID
from flask.ext.openid import OpenID

# See https://flask-wtf.readthedocs.io/en/stable/quickstart.html
# Install from PyPi: sudo -H pip3 install Flask-WTF
from flask_wtf import FlaskForm
from wtforms import validators, widgets, Form, FormField, FieldList, StringField, TextAreaField, SelectField, SelectMultipleField, HiddenField, ValidationError
from wtforms.compat import string_types

# See http://tinydb.readthedocs.io/
# Install from PyPi: sudo -H pip3 install tinydb
from tinydb import TinyDB, Query, where
from tinydb.operations import delete

# See http://rdflib.readthedocs.io/
# On Debian, Ubuntu, etc.:
#   - old version: sudo apt-get install python3-rdflib
#   - latest version: sudo -H pip3 install rdflib
import rdflib
from rdflib import Literal, Namespace
from rdflib.namespace import SKOS, RDF

### Basic setup

app = Flask (__name__)
app.jinja_env.trim_blocks = True
app.jinja_env.lstrip_blocks = True

with open('key', 'r') as f:
    app.secret_key = f.read()

script_dir = os.path.dirname(sys.argv[0])
db = TinyDB(os.path.realpath(os.path.join(script_dir, 'db.json')))
user_db = TinyDB(os.path.realpath(os.path.join(script_dir, 'users.json')))

thesaurus = rdflib.Graph()
thesaurus.parse('simple-unesco-thesaurus.ttl', format='turtle')
UNO = Namespace('http://vocabularies.unesco.org/ontology#')
thesaurus_link = '<a href="http://vocabularies.unesco.org/browser/thesaurus/en/">UNESCO Thesaurus</a>'

oid = OpenID(app, os.path.join(script_dir, 'open-id'))

### Utility functions

def request_wants_json():
    """Returns True if request is for JSON instead of HTML, False otherwise.

    From http://flask.pocoo.org/snippets/45/
    """
    best = request.accept_mimetypes \
        .best_match(['application/json', 'text/html'])
    return best == 'application/json' and \
        request.accept_mimetypes[best] > \
        request.accept_mimetypes['text/html']

def getTermList(uri, broader=True, narrower=True):
    """Recursively finds broader or narrower (or both) terms in the thesaurus.

    Arguments:
        uri (str): URI of term in thesaurus
        broader (Boolean): Whether to search for broader terms (default: True)
        narrower (Boolean): Whether to search for narrower terms (default: True)

    Returns:
        list: Given URI plus those of broader/narrower terms
    """
    terms = list()
    terms.append(uri)
    if broader:
        broader_terms = thesaurus.objects(uri, SKOS.broader)
        for broader_term in broader_terms:
            if not broader_term in terms:
                terms = getTermList(broader_term, narrower=False) + terms
    if narrower:
        narrower_terms = thesaurus.objects(uri, SKOS.narrower)
        for narrower_term in narrower_terms:
            if not narrower_term in terms:
                terms += getTermList(narrower_term, broader=False)
    return terms

def getTermURI(term):
    """Translates a string into the URI of the broadest term in the thesaurus
    that has that string as its preferred label in English.

    Arguments:
        term (str): string to look up

    Returns:
        str: URI of a thesaurus term, if one is found
        None: if no matching term is found
    """
    concept_id = None
    concept_ids = thesaurus.subjects(SKOS.prefLabel, Literal(term, lang="en"))
    priority = 0
    for uri in concept_ids:
        concept_type = thesaurus.value(subject=uri, predicate=RDF.type)
        if concept_type == UNO.Domain and priority < 3:
            concept_id = uri
            priority = 3
        elif concept_type == UNO.MicroThesaurus and priority < 2:
            concept_id = uri
            priority = 2
        elif priority < 1:
            concept_id = uri
            priority = 1
    return concept_id

def getTermNode(uri, filter=list()):
    """Recursively transforms the URI of a term in the thesaurus to a dictionary
    providing the preferred label of the term in English, its corresponding URL
    in the Catalog, and (if applicable) a list of dictionaries corresponding to
    immediately narrower terms in the thesaurus.

    The list of narrower terms can optionally be filtered with a whitelist.

    Arguments:
        uri (str): URI of term in thesaurus
        filter (list): URIs of terms that can be listed as narrower than the
            given one

    Returns:
        dict: Dictionary of two or three items: 'name' (the preferred label of
            the term in English), 'url' (the URL of the corresponding Catalog
            page), 'children' (list of dictionaries, only present if narrower
            terms exist)
    """
    result = dict()
    term = str(thesaurus.preferredLabel(uri, lang='en')[0][1])
    result['name'] = term
    slug = toURLSlug(term)
    result['url'] = url_for('subject', subject=slug)
    narrower_ids = thesaurus.objects(uri, SKOS.narrower)
    children = list()
    if len(filter) > 0:
        for narrower_id in narrower_ids:
            if narrower_id in filter:
                children.append( getTermNode(narrower_id, filter=filter) )
    else:
        for narrower_id in narrower_ids:
            children.append( getTermNode(narrower_id, filter=filter) )
    if len(children) > 0:
        children.sort(key=lambda k: k['name'])
        result['children'] = children
    return result

def getAllTermURIs():
    """Returns a deduplicated list of URIs corresponding to the subject keywords
    in use in the database, plus the URIs of all their broader terms.
    """
    # Get a list of all the keywords used in the database
    schemes = db.table('metadata-schemes')
    Scheme = Query()
    classified_schemes = schemes.search(Scheme.keywords.exists())
    keyword_set = set()
    for classified_scheme in classified_schemes:
        for keyword in classified_scheme['keywords']:
            keyword_set.add(keyword)
    # Transform to URIs
    keyword_uris = set()
    for keyword in keyword_set:
        uri = getTermURI(keyword)
        if uri:
            keyword_uris.add( uri )
    # Get ancestor terms of all these
    full_keyword_uris = set()
    for keyword_uri in keyword_uris:
        if keyword_uri in full_keyword_uris:
            continue
        keyword_uri_list = getTermList(keyword_uri, narrower=False)
        full_keyword_uris.update(keyword_uri_list)
    return full_keyword_uris

def getDBNode(table, id, type):
    """Recursively transforms the internal ID of a record in the database to a
    dictionary providing the entity's title, its corresponding URL in the
    Catalog, and (if applicable) a list of dictionaries corresponding to
    records that are 'children' of the current record.

    Arguments:
        table (database): TinyDB database
        id (str): Internal ID of a Catalog record
        type (str): Type of record ('scheme' or 'tool')

    Returns:
        dict: Dictionary of two or three items: 'name' (the title of the scheme
        or tool), 'url' (the URL of the corresponding Catalog page), 'children'
        (list of child schemes, only present if there are any)
    """
    result = dict()
    entity = table.get(eid=id)
    result['name'] = entity['title']
    result['url'] = url_for(type, number=id)
    if type == 'scheme':
        Main = Query()
        Related = Query()
        child_schemes = table.search(Main.relatedEntities.any( (Related.role == 'parent scheme') & (Related.id == 'msc:m{}'.format(id)) ))
        if len(child_schemes) > 0:
            children = list()
            for child_scheme in child_schemes:
                children.append( getDBNode(table, child_scheme.eid, type) )
            children.sort(key=lambda k: k['name'])
            result['children'] = children
    return result

class Pluralizer:
    """Class for pluralizing nouns. Example uses:

        '{:N corp/us/era}'.format(Pluralizer(0))
        '{:N scheme/s}'.format(Pluralizer(1))
        '{:N sheep}'.format(Pluralizer(2))

    From http://stackoverflow.com/a/27642538
    """
    def __init__(self, value):
        self.value = value

    def __format__(self, formatter):
        formatter = formatter.replace("N", str(self.value))
        start, _, suffixes = formatter.partition("/")
        singular, _, plural = suffixes.rpartition("/")

        return "{}{}".format(start, singular if self.value == 1 else plural)

def toFileSlug(string):
    """Transforms string into slug for use when decomposing the database to
    individual files.
    """
    # Put to lower case, turn spaces to hyphens
    slug = string.strip().lower().replace(' ', '-')
    # Fixes for problem entries
    slug = unicodedata.normalize('NFD', slug)
    slug = slug.encode('ascii', 'ignore')
    slug = slug.decode('utf-8')
    # Strip out non-alphanumeric ASCII characters
    slug = re.sub(r'[^-A-Za-z0-9_]+', '', slug)
    # Remove duplicate hyphens
    slug = re.sub(r'-+', '-', slug)
    # Truncate
    slug = slug[:71]
    return slug

def toURLSlug(string):
    """Transforms string into URL-safe slug."""
    slug = urllib.parse.quote_plus(string)
    return slug

def fromURLSlug(slug):
    """Transforms URL-safe slug back into regular string."""
    string = urllib.parse.unquote_plus(slug)
    return string

def wild2regex(string):
    """Transforms wildcard searches to regular expressions."""
    regex = re.escape(string)
    regex = regex.replace('\*','.*')
    regex = regex.replace('\?','.?')
    return regex

def parseDateRange(string):
    date_split = string.partition('/')
    if date_split[2]:
        return (date_split[0], date_split[2])
    return (string, None)

def formDictList(prefix, fields):
    """Processes families of form elements named according to the scheme
    'prefix-field' or 'prefix-field1'. Numbered fields are processed first,
    then unnumbered fields. The fields are assembled into a list of dictionaries
    where, in each dictionary, the fields form the keys.

    Arguments:
        prefix (str): common first element of form input names
        fields (list): list of strings that occur as the second element of form
            input names

    Returns:
        list: list of dictionaries, where each dictionary contains the fields
            as keys and the submitted content as values.
    """
    current_list = list()
    i = 1
    while '{}-{}{}'.format(prefix, fields[0], i) in request.form:
        instance = dict()
        isWorthKeeping = False
        for field in fields:
            instance[field] = request.form.get('{}-{}{}'.format(prefix, field, i))
            if instance[field]:
                isWorthKeeping = True
        if isWorthKeeping:
            current_list.append(instance)
        i += 1
    instance = dict()
    isWorthKeeping = False
    for field in fields:
        instance[field] = request.form.get('{}-{}'.format(prefix, field))
        if instance[field]:
            isWorthKeeping = True
    if isWorthKeeping:
        current_list.append(instance)
    return current_list

def isValidURL(url):
    """Test whether a URL/email address is well-formed."""
    result = urllib.parse.urlparse(url)
    if result.scheme == 'mailto':
        if re.match(r'[^@\s]+@[^@\s\.]+\.[^@\s]+', result.path):
            return True
    else:
        if result.scheme and result.netloc:
            return True
    return False

def EmailOrURL(form, field):
    """Raise error if URL/email address is not well-formed."""
    result = urllib.parse.urlparse(field.data)
    if result.scheme == 'mailto':
        if not re.match(r'[^@\s]+@[^@\s\.]+\.[^@\s]+', result.path):
            raise ValidationError('That email address does not look quite right.')
    else:
        if not result.scheme:
            raise ValidationError('Please provide the protocol (e.g. "http://", "mailto:").')
        if not result.netloc:
            return ValidationError('That URL does not look quite right.')

class RequiredIf(object):
    """A validator which makes a field required if another field is set and has
    a truthy value, and optional otherwise.
    """
    field_flags = ('optional', )

    def __init__(self, other_field_name, message=None, strip_whitespace=True):
        self.other_field_name = other_field_name
        self.message = message
        if strip_whitespace:
            self.string_check = lambda s: s.strip()
        else:
            self.string_check = lambda s: s

    def __call__(self, form, field):
        other_field = form._fields.get(self.other_field_name)
        if other_field is None:
            raise Exception('No field named "{}" in form'.format(self.other_field_name))
        if bool(other_field.data):
            self.field_flags = ('required', )
            if not field.raw_data or not field.raw_data[0]:
                if self.message is None:
                    message = field.gettext('This field is required.')
                else:
                    message = self.message
                field.errors[:] = []
                raise validators.StopValidation(message)
        elif not field.raw_data or isinstance(field.raw_data[0], string_types) and not self.string_check(field.raw_data[0]):
            field.errors[:] = []
            raise validators.StopValidation()

w3cdate = re.compile(r'^\d{4}(-\d{2}){0,2}$')
def isValidDate(date):
    """Test whether a string is a valid W3C-formatted date."""
    if w3cdate.search(date) is None:
        return False
    return True

def W3CDate(form, field):
    """Test whether a string is a valid W3C-formatted date."""
    if w3cdate.search(field.data) is None:
        raise ValidationError('Please provide the date in yyyy-mm-dd format.')

### Functions made available to templates

@app.context_processor
def utility_processor():
    return { 'toURLSlug': toURLSlug,\
        'fromURLSlug': fromURLSlug,\
        'parseDateRange': parseDateRange }

### User handling

@app.before_request
def lookup_current_user():
    g.user = None
    if 'openid' in session:
        openid = session['openid']
        User = Query()
        g.user = user_db.get(User.openid == openid)

### Front page

@app.route('/')
def hello():
    return render_template('home.html')

### Display metadata scheme

@app.route('/msc/m<int:number>')
@app.route('/msc/m<int:number>/<field>')
def scheme(number, field=None):
    schemes = db.table('metadata-schemes')
    element = schemes.get(eid=number)
    if not element:
        abort(404)

    if request_wants_json():
        if 'identifiers' not in element:
            element['identifiers'] = list()
        element['identifiers'].insert(0,\
            {'id': 'msc:m{}'.format(element.eid), 'scheme': 'RDA-MSCWG'})
        if field:
            if field in element:
                return jsonify({ field: element[field] })
            else:
                return jsonify()
        else:
            return jsonify(element)

    # Here we interpret the meaning of the versions
    versions = None
    if 'versions' in element:
        versions = list()
        for v in element['versions']:
            if not 'number' in v:
                continue
            this_version = v
            this_version['status'] = ''
            if 'issued' in v:
                this_version['date'] = v['issued']
                if 'valid' in v:
                    date_range = parseDateRange(v['valid'])
                    if date_range[1]:
                        this_version['status'] = 'deprecated on '.format(date_range[1])
                    else:
                        this_version['status'] = 'current'
            elif 'valid' in v:
                date_range = parseDateRange(v['valid'])
                this_version['date'] = date_range[0]
                if date_range[1]:
                    this_version['status'] = 'deprecated on '.format(date_range[1])
                else:
                    this_version['status'] = 'current'
            elif 'available' in v:
                this_version['date'] = v['available']
                this_version['status'] = 'proposed'
            versions.append(this_version)
        try:
            versions.sort(key=lambda k: k['date'], reverse=True)
        except KeyError:
            print('WARNING: Scheme msc:m{} has missing version date.'.format(number))
            versions.sort(key=lambda k: k['number'], reverse=True)
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
    Relation = Query()
    related_endorsements = endorsements.search(Endorsement.relatedEntities.any(Relation['id'].matches('msc:m{}(#v.*)?$'.format(number))))
    for entity in related_endorsements:
        entity_id = 'msc:e{}'.format(entity.eid)
        if not entity_id in endorsement_ids:
            endorsement_ids.append(entity_id)
    if len(endorsement_ids) > 0:
        relations['endorsements'] = list()
        for endorsement_id in endorsement_ids:
            entity_number = int(endorsement_id[5:])
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
@app.route('/msc/t<int:number>/<field>')
def tool(number, field=None):
    tools = db.table('tools')
    element = tools.get(eid=number)
    if not element:
        abort(404)

    if request_wants_json():
        if 'identifiers' not in element:
            element['identifiers'] = list()
        element['identifiers'].insert(0,\
            {'id': 'msc:t{}'.format(element.eid), 'scheme': 'RDA-MSCWG'})
        if field:
            if field in element:
                return jsonify({ field: element[field] })
            else:
                return jsonify()
        else:
            return jsonify(element)

    # Here we sanity-check and sort the versions
    versions = None
    if 'versions' in element:
        versions = list()
        for v in element['versions']:
            if not 'number' in v:
                continue
            if not 'issued' in v:
                continue
            v['date'] = v['issued']
            versions.append(v)
        versions.sort(key=lambda k: k['date'], reverse=True)

    # Here we assemble information about related entities
    schemes = db.table('metadata-schemes')
    organizations = db.table('organizations')
    relations = dict()
    if 'relatedEntities' in element:
        for entity in element['relatedEntities']:
            if entity['role'] == 'supported scheme':
                if not 'supported schemes' in relations:
                    relations['supported schemes'] = list()
                entity_number = int(entity['id'][5:])
                element_record = schemes.get(eid=entity_number)
                if element_record:
                    relations['supported schemes'].append(element_record)

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

    return render_template('tool.html', record=element, versions=versions,\
        relations=relations)

### Display organization

@app.route('/msc/g<int:number>')
@app.route('/msc/g<int:number>/<field>')
def organization(number, field=None):
    organizations = db.table('organizations')
    element = organizations.get(eid=number)
    if not element:
        abort(404)

    if request_wants_json():
        if 'identifiers' not in element:
            element['identifiers'] = list()
        element['identifiers'].insert(0,\
            {'id': 'msc:g{}'.format(element.eid), 'scheme': 'RDA-MSCWG'})
        if field:
            if field in element:
                return jsonify({ field: element[field] })
            else:
                return jsonify()
        else:
            return jsonify(element)
    else:
        flash('The URL you requested is part of the Catalog API and has no HTML equivalent.', 'error')
        return redirect(url_for('hello'))

### Display mapping

@app.route('/msc/c<int:number>')
@app.route('/msc/c<int:number>/<field>')
def mapping(number, field=None):
    mappings = db.table('mappings')
    element = mappings.get(eid=number)
    if not element:
        abort(404)

    if request_wants_json():
        if 'identifiers' not in element:
            element['identifiers'] = list()
        element['identifiers'].insert(0,\
            {'id': 'msc:c{}'.format(element.eid), 'scheme': 'RDA-MSCWG'})
        if field:
            if field in element:
                return jsonify({ field: element[field] })
            else:
                return jsonify()
        else:
            return jsonify(element)
    else:
        flash('The URL you requested is part of the Catalog API and has no HTML equivalent.', 'error')
        return redirect(url_for('hello'))

### Display endorsement

@app.route('/msc/e<int:number>')
@app.route('/msc/e<int:number>/<field>')
def endorsement(number, field=None):
    endorsements = db.table('endorsements')
    element = endorsements.get(eid=number)
    if not element:
        abort(404)

    if request_wants_json():
        if 'identifiers' not in element:
            element['identifiers'] = list()
        element['identifiers'].insert(0,\
            {'id': 'msc:e{}'.format(element.eid), 'scheme': 'RDA-MSCWG'})
        if field:
            if field in element:
                return jsonify({ field: element[field] })
            else:
                return jsonify()
        else:
            return jsonify(element)
    else:
        flash('The URL you requested is part of the Catalog API and has no HTML equivalent.', 'error')
        return redirect(url_for('hello'))

### Per-subject lists of standards

@app.route('/subject/<subject>')
def subject(subject):
    # If people start using geographical keywords, the following will need more sophistication
    query_string = fromURLSlug(subject)
    results = list()

    # Interpret subject
    term_list = list()
    if subject == 'Multidisciplinary':
        term_list.append('Multidisciplinary')
    else:
        # - Translate term into concept ID
        concept_id = getTermURI(query_string)
        if not concept_id:
            flash('The subject "{}" was not found in the {}.\n'.format(\
                query_string, thesaurus_link), 'error')
            return render_template('search-results.html', title=query_string)
        # - Find list of broader and narrower terms
        term_uri_list = getTermList(concept_id)
        for term_uri in term_uri_list:
            term = str(thesaurus.preferredLabel(term_uri, lang='en')[0][1])
            if not term in term_list:
                term_list.append(term)

    # Search for matching schemes
    schemes = db.table('metadata-schemes')
    Scheme = Query()
    results = schemes.search(Scheme.keywords.any(term_list))
    no_of_hits = len(results)
    if no_of_hits == 0:
        flash('Found 0 schemes.', 'error')
    else:
        flash('Found {:N scheme/s}.'.format(Pluralizer(no_of_hits)))
        results.sort(key=lambda k: k['title'].lower())
    return render_template('search-results.html', title=query_string, results=results)

### Per-funder/maintainer lists of standards

@app.route('/funder/g<int:funder>')
@app.route('/maintainer/g<int:maintainer>')
@app.route('/user/g<int:user>')
def group(funder=None, maintainer=None, user=None):
    id = 0
    role = ''
    verb = ''
    if funder:
        id = funder
        role = 'funder'
        verb = 'funded'
    elif maintainer:
        id = maintainer
        role = 'maintainer'
        verb = 'maintained'
    elif user:
        id = user
        role = 'user'
        verb = 'used'
    # Do the search
    organizations = db.table('organizations')
    element = organizations.get(eid=id)
    title = element['name']
    schemes = db.table('metadata-schemes')
    Scheme = Query()
    Relation = Query()
    results = schemes.search(Scheme.relatedEntities.any(\
        (Relation.role == role) & (Relation.id == 'msc:g{}'.format(id)) ))
    no_of_hits = len(results)
    if no_of_hits > 0:
        flash('Found {:N scheme/s} {} by this organization.'.format(\
            Pluralizer(no_of_hits), verb))
    else:
        flash('No schemes found {} by this organization.'.format(verb), 'error')
    return render_template('search-results.html', title=title, results=results)

### Per-datatype lists of standards
@app.route('/datatype/<dataType>')
def dataType(dataType):
    query_string = fromURLSlug(dataType)
    schemes = db.table('metadata-schemes')
    Scheme = Query()
    results = schemes.search(Scheme.dataTypes.any([ query_string ]))
    no_of_hits = len(results)
    if no_of_hits > 0:
        flash('Found {:N scheme/s} used for this type of data.'.format(\
            Pluralizer(no_of_hits)))
    else:
        flash('No schemes have been reported to be used for this type of data.', 'error')
    return render_template('search-results.html', title=query_string, results=results)

### List of standards

@app.route('/scheme-index')
def scheme_index():
    schemes = db.table('metadata-schemes')
    Scheme = Query()
    Entity = Query()
    parent_schemes = schemes.search(Scheme.relatedEntities.all(Entity.role != 'parent scheme'))
    scheme_tree = list()
    for scheme in parent_schemes:
        scheme_tree.append( getDBNode(schemes, scheme.eid, 'scheme') )
    scheme_tree.sort(key=lambda k: k['name'].lower())
    return render_template('contents.html', title='List of metadata standards',\
        tree=scheme_tree)

### List of tools

@app.route('/tool-index')
def tool_index():
    tools = db.table('tools')
    Tool = Query()
    Entity = Query()
    all_tools = tools.all()
    tool_tree = list()
    for tool in all_tools:
        tool_tree.append( getDBNode(tools, tool.eid, 'tool') )
    tool_tree.sort(key=lambda k: k['name'].lower())
    return render_template('contents.html', title='List of metadata tools',\
        tree=tool_tree)

### Subject index

@app.route('/subject-index')
def subject_index():
    full_keyword_uris = getAllTermURIs()
    subject_tree = list()
    domains = thesaurus.subjects(RDF.type, UNO.Domain)
    for domain in domains:
        if domain in full_keyword_uris:
            subject_tree.append( getTermNode(domain, filter=full_keyword_uris) )
    subject_tree.sort(key=lambda k: k['name'].lower())
    subject_tree.insert(0, { 'name': 'Multidisciplinary',\
        'url': url_for('subject', subject='Multidisciplinary')})
    return render_template('contents.html', title='Index of subjects',\
        tree=subject_tree)

### Search form

@app.route('/search', methods=['GET', 'POST'])
def search():
    schemes = db.table('metadata-schemes')
    organizations = db.table('organizations')
    if request.method == 'POST':
        title = 'Search results'
        results = list()
        Scheme = Query()
        no_of_queries = 0

        if request.form['title'] != '':
            no_of_queries += 1
            title_query = wild2regex(request.form['title'])
            title_search = schemes.search(Scheme.title.search(title_query))
            no_of_hits = len(title_search)
            if no_of_hits > 0:
                flash('Found {:N scheme/s} with title "{}". '.format(\
                    Pluralizer(no_of_hits), request.form['title']))
                results.extend(title_search)
            else:
                flash('No schemes found with title "{}". '.format(\
                    request.form['title']), 'error')

        if request.form['keyword'] != '' :
            no_of_queries += 1
            # Interpret subject
            term_list = list()
            if request.form['keyword'] == 'Multidisciplinary':
                term_list.append('Multidisciplinary')
            else:
                # - Translate term into concept ID
                concept_id = getTermURI(request.form['keyword'])
                if not concept_id:
                    flash('The subject "{}" was not found in the {}.\n'.format(\
                        request.form['keyword'], thesaurus_link), 'error')
                # - Find list of broader and narrower terms
                term_uri_list = getTermList(concept_id)
                for term_uri in term_uri_list:
                    term = str(thesaurus.preferredLabel(term_uri, lang='en')[0][1])
                    if not term in term_list:
                        term_list.append(term)

            # Search for matching schemes
            subject_search = schemes.search(Scheme.keywords.any(term_list))
            no_of_hits = len(subject_search)
            if no_of_hits > 0:
                flash('Found {:N scheme/s} related to {}. '.format(\
                    Pluralizer(no_of_hits), request.form['keyword']))
                results.extend(subject_search)
            else:
                flash('No schemes found related to {}. '.format(\
                    request.form['keyword']), 'error')

        if request.form['id'] != '':
            no_of_queries += 1
            if request.form['id'][:5] == 'msc:m':
                id_search = schemes.get(eid=int(request.form['id'][5:]))
            else:
                Identifier = Query()
                id_search = schemes.search(Scheme.identifiers.any(Identifier.id == request.form['id']))
            no_of_hits = len(id_search)
            if no_of_hits > 0:
                flash('Found {:N scheme/s} with identifier "{}". '.format(\
                    Pluralizer(no_of_hits), request.form['id']))
                results.extend(id_search)
            else:
                flash('No schemes found with identifier "{}". '.format(\
                    request.form['id']), 'error')

        if 'funder' in request.form and request.form['funder'] != '':
            no_of_queries += 1
            # Interpret search
            Funder = Query()
            matching_funders = list()
            funder_query = wild2regex(request.form['funder'])
            funder_search = organizations.search(Funder.name.search(funder_query))
            for funder in funder_search:
                matching_funders.append('msc:g{}'.format(funder.eid))
            if len(matching_funders) == 0:
                flash('No funders found called "{}" .'.format(\
                    request.form['funder']), 'error')
            else:
                Relation = Query()
                with_funder = list()
                for funder_id in matching_funders:
                    with_funder.extend(schemes.search(\
                        Scheme.relatedEntities.any(\
                            (Relation.role == 'funder') & (Relation.id == funder_id) )))
                no_of_hits = len(with_funder)
                if no_of_hits > 0:
                    flash('Found {:N scheme/s} with funder "{}". '.format(\
                        Pluralizer(no_of_hits), request.form['funder']))
                    results.extend(with_funder)
                else:
                    flash('No schemes found with funder "{}". '.format(\
                        request.form['funder']), 'error')

        if 'dataType' in request.form and request.form['dataType'] != '':
            no_of_queries += 1
            type_search = schemes.search(Scheme.dataTypes.any([ request.form['dataType'] ]))
            no_of_hits = len(type_search)
            if no_of_hits > 0:
                flash('Found {:N scheme/s} associated with {}. '.format(\
                    Pluralizer(no_of_hits), request.form['dataType']))
                results.extend(type_search)
            else:
                flash('No schemes found associated with {}. '.format(\
                    request.form['dataType']), 'error')

        # Are there any duplicates?
        result_eids = list()
        result_list = list()
        for result in results:
            if not result.eid in result_eids:
                result_list.append(result)
                result_eids.append(result.eid)
        no_of_hits = len(result_list)
        if no_of_queries > 1:
            flash('Found {:N scheme/s} in total. '.format(Pluralizer(no_of_hits)))
        if no_of_hits == 1:
            # Go direct to that page
            result = result_list[0]
            return redirect(url_for('scheme', number=result.eid))
        else:
            if no_of_hits > 1:
                result_list.sort(key=lambda k: k['title'].lower())
            # Show results list
            return render_template('search-results.html', title=title, results=result_list)

    else:
        # Title, identifier, funder, dataType help
        all_schemes = schemes.all()
        title_set = set()
        id_set = set()
        funder_set = set()
        type_set = set()
        for scheme in all_schemes:
            title_set.add(scheme['title'])
            id_set.add('msc:m{}'.format(scheme.eid))
            if 'identifiers' in scheme:
                for identifier in scheme['identifiers']:
                    id_set.add(identifier['id'])
            if 'dataTypes' in scheme:
                for type in scheme['dataTypes']:
                    type_set.add(type)
            if 'relatedEntities' in scheme:
                for entity in scheme['relatedEntities']:
                    if entity['role'] == 'funder':
                        org_id = entity['id']
                        funder = organizations.get(eid=int(org_id[5:]))
                        if funder:
                            funder_set.add(funder['name'])
                        else:
                            print('Could not look up organization with eid {}. '.format(org_id[5:]))
        title_list = list(title_set)
        title_list.sort(key=lambda k: k.lower())
        id_list = list(id_set)
        id_list.sort()
        funder_list = list(funder_set)
        funder_list.sort(key=lambda k: k.lower())
        type_list = list(type_set)
        type_list.sort(key=lambda k: k.lower())
        # Subject help
        full_keyword_uris = getAllTermURIs()
        subject_set = set()
        for uri in full_keyword_uris:
            subject_set.add( str(thesaurus.preferredLabel(uri, lang='en')[0][1]) )
        subject_set.add('Multidisciplinary')
        subject_list = list(subject_set)
        subject_list.sort()
        return render_template('search-form.html', titles=title_list,\
            subjects=subject_list, ids=id_list, funders=funder_list,\
            dataTypes=type_list)

### Corresponding query interface

@app.route('/query/schemes', methods=['POST'])
def scheme_query():
    if not request_wants_json():
        flash('The URL you requested is part of the Catalog API. ' + \
            'Please use this search form instead.', 'error')
        return redirect(url_for('search'))

    schemes = db.table('metadata-schemes')
    organizations = db.table('organizations')
    results = list()
    Scheme = Query()

    if 'title' in request.form and request.form['title'] != '':
        title_search = schemes.search(Scheme.title.search(request.form['title']))
        no_of_hits = len(title_search)
        if no_of_hits > 0:
            results.extend(title_search)

    if 'keyword' in request.form and request.form['keyword'] != '' :
        # Interpret subject
        term_list = list()
        if request.form['keyword'] == 'Multidisciplinary':
            term_list.append('Multidisciplinary')
        else:
            # - Translate term into concept ID
            concept_id = getTermURI(request.form['keyword'])
            # - Find list of broader and narrower terms
            term_uri_list = getTermList(concept_id)
            for term_uri in term_uri_list:
                term = str(thesaurus.preferredLabel(term_uri, lang='en')[0][1])
                if not term in term_list:
                    term_list.append(term)

        # Search for matching schemes
        subject_search = schemes.search(Scheme.keywords.any(term_list))
        no_of_hits = len(subject_search)
        if no_of_hits > 0:
            results.extend(subject_search)

    if 'keyword-id' in request.form and request.form['keyword-id'] != '' :
        term_list = list()
        # Find list of broader and narrower terms
        term_uri_list = getTermList(request.form['keyword-id'])
        # Translate into keywords
        for term_uri in term_uri_list:
            label_pairs = thesaurus.preferredLabel(term_uri, lang='en')
            if len(label_pairs) > 0:
                term = str(label_pairs[0][1])
                if not term in term_list:
                    term_list.append(term)

        # Search for matching schemes
        subject_search = schemes.search(Scheme.keywords.any(term_list))
        no_of_hits = len(subject_search)
        if no_of_hits > 0:
            results.extend(subject_search)

    if 'id' in request.form and request.form['id'] != '':
        if request.form['id'][:5] == 'msc:m':
            id_search = schemes.get(eid=int(request.form['id'][5:]))
        else:
            Identifier = Query()
            id_search = schemes.search(Scheme.identifiers.any(Identifier.id == request.form['id']))
        no_of_hits = len(id_search)
        if no_of_hits > 0:
            results.extend(id_search)

    if 'funder' in request.form and request.form['funder'] != '':
        # Interpret search
        Funder = Query()
        matching_funders = list()
        funder_search = organizations.search(Funder.name.search(request.form['funder']))
        for funder in funder_search:
            matching_funders.append('msc:g{}'.format(funder.eid))
        if len(matching_funders) > 0:
            Relation = Query()
            with_funder = list()
            for funder_id in matching_funders:
                with_funder.extend(\
                    schemes.search(Scheme.relatedEntities.any(\
                        (Relation.role == 'funder') & (Relation.id == funder_id) )))
            no_of_hits = len(with_funder)
            if no_of_hits > 0:
                results.extend(with_funder)

    if 'funder-id' in request.form and request.form['funder-id'] != '':
        # Interpret search
        Funder = Query()
        Identifier = Query()
        matching_funders = list()
        funder_search = organizations.search(\
            Funder.identifiers.any(Identifier.id == request.form['funder-id']))
        for funder in funder_search:
            matching_funders.append('msc:g{}'.format(funder.eid))
        if len(matching_funders) > 0:
            Relation = Query()
            with_funder = list()
            for funder_id in matching_funders:
                with_funder.extend(schemes.search(\
                    Scheme.relatedEntities.any(\
                        (Relation.role == 'funder') & (Relation.id == funder_id) )))
            no_of_hits = len(with_funder)
            if no_of_hits > 0:
                results.extend(with_funder)

    if 'dataType' in request.form and request.form['dataType'] != '':
        type_search = schemes.search(Scheme.dataTypes.any([ request.form['dataType'] ]))
        no_of_hits = len(type_search)
        if no_of_hits > 0:
            results.extend(type_search)

    # We just want the IDs
    result_eids = list()
    result_list = list()
    for result in results:
        if not result.eid in result_eids:
            result_list.append('msc:m{}'.format(result.eid))
            result_eids.append(result.eid)
    result_list.sort()
    # Show results list
    return jsonify({ 'ids': result_list })

### User login

@app.route('/login', methods=['GET', 'POST'])
@oid.loginhandler
def login():
    if g.user is not None:
        return redirect(oid.get_next_url())
    if request.method == 'POST':
        openid = request.form.get('openid')
        if openid:
            return oid.try_login(openid, ask_for=['email', 'nickname'],\
                ask_for_optional=['fullname'])
    error = oid.fetch_error()
    if error:
        flash(error, 'error')
    return render_template('login.html', next=oid.get_next_url())

@oid.after_login
def create_or_login(resp):
    session['openid'] = resp.identity_url
    User = Query()
    user = user_db.get(User.openid == resp.identity_url)
    if user:
        flash('Successfully signed in.')
        g.user = user
        return redirect(oid.get_next_url())
    return redirect(url_for('create_profile', next=oid.get_next_url(),\
        name=resp.fullname or resp.nickname, email=resp.email))

@app.route('/create-profile', methods=['GET', 'POST'])
def create_profile():
    if g.user is not None or 'openid' not in session:
        if 'openid' not in session:
            flash('OpenID sign-in failed, sorry.', 'error')
        return redirect(url_for('hello'))
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        if not name:
            flash('You must provide a user name.', 'error')
        elif '@' not in email:
            flash('You must enter a valid email address.', 'error')
        else:
            user_db.insert({'name': name, 'email': email, 'openid': session['openid']})
            flash('Profile successfully created.')
            return redirect(oid.get_next_url())
    return render_template('create-profile.html', next=oid.get_next_url())

@app.route('/logout')
def logout():
    session.pop('openid', None)
    flash('You were signed out')
    return redirect(oid.get_next_url())

### Editing screens

# Utility functions for WTForms implementation

def clean_dict(data):
    """Takes dictionary and recursively removes fields where the value is (a)
    an empty string, (b) an empty list, (c) a dictionary wherein all the values
    are empty, (d) null.
    """
    for key, value in data.copy().items():
        if isinstance(value, dict):
            new_value = clean_dict(value)
            if len(new_value) == 0:
                del data[key]
            else:
                data[key] = new_value
        elif isinstance(value, list):
            if len(value) == 0:
                del data[key]
            else:
                clean_list = list()
                for item in value:
                    if isinstance(item, dict):
                        new_item = clean_dict(item)
                        if len(new_item) > 0:
                            clean_list.append(new_item)
                    elif item:
                        clean_list.append(item)
                if len(clean_list) > 0:
                    data[key] = clean_list
                else:
                    del data[key]
        elif value is '':
            del data[key]
        elif value is None:
            del data[key]
        elif key is 'csrf_token':
            del data[key]
    return data

relations_msc_form = {\
    'parent scheme': 'parent_schemes',\
    'maintainer': 'maintainers',\
    'funder': 'funders',\
    'user': 'users',\
    'supported scheme': 'supported_schemes',\
    'input scheme': 'input_schemes',\
    'output scheme': 'output_schemes',\
    'endorsed scheme': 'endorsed_schemes',\
    'originator': 'originators',\
    }

relations_form_msc = {v: k for k, v in relations_msc_form.items()}

def msc_to_form(msc_data):
    """Transforms data from MSC database into the data structure used by the
    web forms.

    Arguments:
        msc_data (dict): Record from the MSC database.

    Returns:
        dict: Dictionary suitable for populating a web form.
    """
    form_data = dict()
    for k, v in msc_data.items():
        if k == 'relatedEntities':
            for entity in v:
                role = entity['role']
                mapped_role = relations_msc_form[role]
                if mapped_role not in form_data:
                    form_data[mapped_role] = list()
                id_tuple = entity['id'].partition('#v')
                if mapped_role == 'endorsed_schemes':
                    form_data[mapped_role].append({'id': id_tuple[0], 'version': id_tuple[2]})
                else:
                    form_data[mapped_role].append(id_tuple[0])
        elif k == 'valid':
            valid_tuple = v.partition('/')
            form_data['valid_from'] = valid_tuple[0]
            form_data['valid_to'] = valid_tuple[2]
        elif k == 'versions':
            if k not in form_data:
                form_data[k] = list()
            for version in v:
                mapped_version = dict()
                for key, value in version.items():
                    if key == 'valid':
                        valid_tuple = value.partition('/')
                        mapped_version['valid_from'] = valid_tuple[0]
                        mapped_version['valid_to'] = valid_tuple[2]
                    else:
                        mapped_version[key] = value
                    if key == 'number':
                        mapped_version['number_old'] = value
                form_data[k].append(mapped_version)
        else:
            form_data[k] = v
    # Ensure there is a blank entry at the end of the following lists
    for l in ['keywords', 'dataTypes', 'types']:
        if l in form_data:
            form_data[l].append('')
    if 'locations' in form_data:
        form_data['locations'].append({'url': '', 'type': '' })
    if 'identifiers' in form_data:
        form_data['identifiers'].append({'id': '', 'scheme': '' })
    if 'versions' in form_data:
        form_data['versions'].append({'number': '', 'issued': ''})
    if 'creators' in form_data:
        form_data['creators'].append({'fullName': '', 'givenName': '', 'familyName': ''})
    if 'endorsed_schemes' in form_data:
        form_data['endorsed_schemes'].append({'id': '', 'version': '' })
    return form_data

def form_to_msc(form_data, element):
    """Transforms data from web form into the MSC data model, supplemented by
    data that the form does not supply.

    Arguments:
        form_data (dict): Data from the form.
        element (dict or None): Existing record from the database that the
            form_data is intended to update.

    Returns:
        dict: Dictionary suitable for inclusion in the database
    """
    msc_data = dict()
    clean_data = clean_dict(form_data)
    has_tl_valid_from = False
    has_tl_valid_to = False
    for k, v in clean_data.items():
        if k in relations_form_msc:
            if 'relatedEntities' not in msc_data:
                msc_data['relatedEntities'] = list()
            role = relations_form_msc[k]
            for item in v:
                if isinstance(item, dict):
                    if 'version' in item:
                        id_string = '{}#v{}'.format(item['id'], item['version'])
                    else:
                        id_string = item['id']
                else:
                    id_string = item
                msc_data['relatedEntities'].append({'id': id_string, 'role': role})
        elif k == 'valid_from':
            has_tl_valid_from = True
        elif k == 'valid_to':
            has_tl_valid_to = True
        elif k == 'versions':
            if k not in msc_data:
                msc_data[k] = list()
            for version in v:
                mapped_version = dict()
                has_vn_valid_from = False
                has_vn_valid_to = False
                for key, value in version.items():
                    if key == 'valid_from':
                        has_vn_valid_from = True
                    elif key == 'valid_to':
                        has_vn_valid_to = True
                    elif key == 'number_old':
                        # Restore information from existing record
                        if element and 'versions' in element:
                            for release in element['versions']:
                                if 'number' in release and str(release['number']) == str(value):
                                    overrides = {i: j for i, j in release.items()\
                                        if i not in ['number', 'available', 'issued', 'valid']}
                                    mapped_version.update(overrides)
                                    break
                    else:
                        mapped_version[key] = value
                if has_vn_valid_from:
                    if has_vn_valid_to:
                        mapped_version['valid'] = '{}/{}'.format(version['valid_from'], version['valid_to'])
                    else:
                        mapped_version['valid'] = version['valid_from']
                msc_data[k].append(mapped_version)
        else:
            msc_data[k] = v
        if has_tl_valid_from:
            if has_tl_valid_to:
                msc_data['valid'] = '{}/{}'.format(clean_data['valid_from'], clean_data['valid_to'])
            else:
                msc_data['valid'] = clean_data['valid_from']
    # Restore other data that never appears in the form
    for k in ['slug']:
        if element and k in element:
            msc_data[k] = element[k]
    return msc_data

def fix_slug(record, series):
    """If the given record does not have a slug value, attempts to generate one.

    Arguments:
        record (dict): Dictionary using MSC data model.
        series (str): One of 'm', 'g', 't', 'c', 'e', referring to the type of
            record.

    Returns:
        dict: Dictionary using MSC data model.
    """
    # Exit if slug already exists
    if 'slug' in record:
        return record
    # Otherwise attempt to generate from existing data
    tables = {\
        'm': 'metadata-schemes',\
        'g': 'organizations',\
        't': 'tools',\
        'c': 'mappings',\
        'e': 'endorsements' }
    slug = None
    if series == 'm' or series == 't':
        if 'title' in record:
            slug = toFileSlug(record['title'])
    elif series == 'g':
        if 'name' in record:
            slug = toFileSlug(record['title'])
    elif series == 'e':
        if 'citation' in record:
            slug = toFileSlug(record['citation'])
    elif series == 'c':
        if 'relatedEntities' in record:
            slug_from = ''
            slug_to = ''
            schemes = db.table(tables['m'])
            for entity in record['relatedEntities']:
                eid = entity['id'][5:]
                if entity['role'] == 'input scheme':
                    element = schemes.get(eid=eid)
                    if 'slug' in element:
                        slug_from = element['slug']
                elif entity['role'] == 'output scheme':
                    element = schemes.get(eid=eid)
                    if 'slug' in element:
                        slug_to = element['slug']
            if slug_from and slug_to:
                slug = '-'.join(slug_from.split('-')[:3])
                slug += '_TO_'
                slug += '-'.join(slug_to.split('-')[:3])
    else:
        raise Exception('Unrecognized record series "{}"; cannot fix slug.'.format(series))
    # Exit if this didn't work
    if not slug:
        return record
    # Ensure uniqueness then apply
    table = db.table(tables[series])
    i = ''
    while len(table.search(Query().slug == (slug + str(i)))) > 0:
        if i == '':
            i = 1
        else:
            i += 1
    else:
        record['slug'] = slug
    return record

computing_platforms = ['Windows', 'Mac OS X', 'Linux', 'BSD', 'cross-platform']

# Top 10 languages according to http://www.langpop.com/ in 2013
programming_languages = [ 'C', 'Java', 'PHP', 'JavaScript', 'C++', 'Python',
    'Shell', 'Ruby', 'Objective-C', 'C#' ]
programming_languages.sort()

id_scheme_list = [ 'DOI' ]

# Common form snippets

class NativeDateField(StringField):
    widget = widgets.Input(input_type='date')
    validators = [validators.Optional(), W3CDate]

class LocationForm(Form):
    url = StringField('URL', validators=[RequiredIf('type'), EmailOrURL])
    type = SelectField('Type', validators=[RequiredIf('url')])

class FreeLocationForm(Form):
    url = StringField('URL', validators=[RequiredIf('type'), EmailOrURL])
    # Regex for location types allowed for mappings
    allowed_locations = r'(document|library \([^)]+\)|executable \([^)]+\))'
    type_help = 'Must be one of "document", "library (<language>)", "executable (<platform>)".'
    type = StringField('Type', validators=[RequiredIf('url'),\
        validators.Regexp(allowed_locations, message=type_help)])

class SampleForm(Form):
    title = StringField('Title', validators=[RequiredIf('url')])
    url = StringField('URL', validators=[RequiredIf('title'), EmailOrURL])

class IdentifierForm(Form):
    id = StringField('ID')
    scheme = StringField('ID scheme')

class VersionForm(Form):
    number = StringField('Version number', validators=[RequiredIf('issued'), RequiredIf('available'), RequiredIf('valid_from'), validators.Length(max=20)])
    number_old = HiddenField(validators=[validators.Length(max=20)])
    issued = NativeDateField('Date published')
    available = NativeDateField('Date released as draft/proposal')
    valid_from = NativeDateField('Date considered current')
    valid_to = NativeDateField('until')

class SchemeVersionForm(Form):
    schemes = db.table('metadata-schemes')
    scheme_choices = [('', '')]
    for scheme in schemes.all():
        scheme_choices.append( ('msc:m{}'.format(scheme.eid), scheme['title']) )
    scheme_choices.sort(key=lambda k: k[1].lower())

    id = SelectField('Metadata scheme', choices=scheme_choices)
    version = StringField('Version')

class CreatorForm(Form):
    fullName = StringField('Full name')
    givenName = StringField('Given name(s)')
    familyName = StringField('Family name')

# Editing metadata schemes

class SchemeForm(FlaskForm):
    schemes = db.table('metadata-schemes')
    scheme_choices = list()
    for scheme in schemes.all():
        scheme_choices.append( ('msc:m{}'.format(scheme.eid), scheme['title']) )
    scheme_choices.sort(key=lambda k: k[1].lower())
    organizations = db.table('organizations')
    organization_choices = list()
    for organization in organizations.all():
        organization_choices.append( ('msc:g{}'.format(organization.eid), organization['name']) )
    organization_choices.sort(key=lambda k: k[1].lower())

    title = StringField('Name of metadata scheme')
    description = TextAreaField('Description')
    keywords = FieldList(StringField('Subject area'), 'Subject areas', min_entries=1)
    dataTypes = FieldList(StringField('URL or term'), 'Data types', min_entries=1)
    parent_schemes = SelectMultipleField('Parent metadata scheme(s)', choices=scheme_choices)
    maintainers = SelectMultipleField('Organizations that maintain this scheme', choices=organization_choices)
    funders = SelectMultipleField('Organizations that funded this scheme', choices=organization_choices)
    users = SelectMultipleField('Organizations that use this scheme', choices=organization_choices)
    locations = FieldList(FormField(LocationForm), 'Relevant links', min_entries=1)
    samples = FieldList(FormField(SampleForm), 'Sample records conforming to this scheme', min_entries=1)
    identifiers = FieldList(FormField(IdentifierForm), 'Identifiers for this scheme', min_entries=1)
    versions = FieldList(FormField(VersionForm), 'Version history', min_entries=1)

@app.route('/edit/m<int:number>', methods=['GET', 'POST'])
def edit_scheme(number):
    if g.user is None:
        flash('You must sign in before making any changes.', 'error')
        return redirect(url_for('login'))
    schemes = db.table('metadata-schemes')
    organizations = db.table('organizations')
    element = schemes.get(eid=number)
    version = request.values.get('version')
    if version and request.referrer == request.base_url:
        # This is the version screen, opened from the main screen
        flash('Only provide information here that is different from the information in the main (non-version-specific) record.')
    # Subject help
    all_keyword_uris = set()
    for generator in [thesaurus.subjects(RDF.type, UNO.Domain),\
        thesaurus.subjects(RDF.type, UNO.MicroThesaurus),\
        thesaurus.subjects(RDF.type, SKOS.Concept)]:
        for uri in generator:
            all_keyword_uris.add(uri)
    subject_set = set()
    for uri in all_keyword_uris:
        subject_set.add( str(thesaurus.preferredLabel(uri, lang='en')[0][1]) )
    subject_set.add('Multidisciplinary')
    subject_list = list(subject_set)
    subject_list.sort()
    # Data type help
    type_set = set()
    for scheme in schemes.all():
        if 'dataTypes' in scheme:
            for type in scheme['dataTypes']:
                type_set.add(type)
    type_list = list(type_set)
    type_list.sort(key=lambda k: k.lower())
    if element:
        # Translate from internal data model to form data
        if version:
            for release in element['versions']:
                if 'number' in release and str(release['number']) == str(version):
                    form = SchemeForm(request.form, data=msc_to_form(release))
                    break
            else:
                form = SchemeForm(request.form)
            del form['versions']
        else:
            form = SchemeForm(request.form, data=msc_to_form(element))
    else:
        if number != 0:
            return redirect(url_for('edit_tool', number=0))
        form = SchemeForm(request.form)
    for f in form.locations:
        f['type'].choices = [('', ''),
                ('document', 'document'), ('website', 'website'),
                ('RDA-MIG', 'RDA MIG Schema'), ('DTD', 'XML/SGML DTD'),
                ('XSD', 'XML Schema'), ('RDFS', 'RDF Schema')]
    for f in form.keywords:
        f.validators = [validators.Optional(), validators.AnyOf(subject_list, 'Value must match an English preferred label in the {}.'.format(thesaurus_link))]
    # Processing the request
    if request.method == 'POST' and form.validate():
        # TODO: apply logging and version control
        # Translate form data into internal data model
        msc_data = form_to_msc(form.data, element)
        if version:
            # Editing the version-specific overrides
            if element and 'versions' in element:
                version_list = element['versions']
                for index, item in enumerate(version_list):
                    if str(item['number']) == str(version):
                        version_dict = {k: v for k, v in item.items()\
                            if k in ['number', 'available', 'issued', 'valid']}
                        version_dict.update(msc_data)
                        version_list[index] = version_dict
                        Scheme = Query()
                        Version = Query()
                        schemes.update({'versions': version_list},\
                            Scheme.versions.any(Version.number == version),\
                            eids=[number])
                        flash('Successfully updated record for version {}.'.format(version), 'success')
                        break
                else:
                    # This version is not in the list
                    flash('Could not apply changes. Have you saved details for version {} in the main record?'.format(version), 'error')
            else:
                # The version list or the main record is missing
                flash('Could not apply changes. Have you saved details for version {} in the main record?'.format(version), 'error')
            return redirect('{}?version={}'.format(url_for('edit_scheme', number=number), version))
        elif element:
            # Editing an existing record
            msc_data = fix_slug(msc_data, 'm')
            for key in element:
                schemes.update(delete(key), eids=[number])
            schemes.update(msc_data, eids=[number])
            flash('Successfully updated record.', 'success')
        else:
            # Adding a new record
            msc_data = fix_slug(msc_data, 'm')
            number = schemes.insert(msc_data)
            flash('Successfully added record.', 'success')
        return redirect(url_for('edit_scheme', number=number))
    if form.errors:
        flash('Could not save changes as there {:/was an error/were N errors}. See below for details.'.format(Pluralizer(len(form.errors))), 'error')
    return render_template('edit-scheme.html', form=form, eid=number,\
        version=version, subjects=subject_list, dataTypes=type_list,\
        idSchemes=id_scheme_list)

# Editing organizations

class OrganizationForm(FlaskForm):
    organization_choices = [('standards body', 'standards body'),
            ('archive', 'archive'),
            ('professional group', 'professional group'),
            ('coordination group', 'coordination group')]

    name = StringField('Name of organization')
    description = TextAreaField('Description')
    types = SelectMultipleField('Type of organization', choices=organization_choices)
    locations = FieldList(FormField(LocationForm), 'Relevant links', min_entries=1)
    identifiers = FieldList(FormField(IdentifierForm), 'Identifiers for this organization', min_entries=1)

@app.route('/edit/g<int:number>', methods=['GET', 'POST'])
def edit_organization(number):
    if g.user is None:
        flash('You must sign in before making any changes.', 'error')
        return redirect(url_for('login'))
    organizations = db.table('organizations')
    element = organizations.get(eid=number)
    # Types and ID schemes
    location_type_list = ['website', 'email']
    if element:
        # Translate from internal data model to form data
        form = OrganizationForm(request.form, data=msc_to_form(element))
    else:
        if number != 0:
            return redirect(url_for('edit_organization', number=0))
        form = OrganizationForm(request.form)
    for f in form.locations:
        f['type'].choices = [('', ''), ('website', 'website'), ('email', 'email address')]
    # Processing the request
    if request.method == 'POST' and form.validate():
        # Translate form data into internal data model
        msc_data = form_to_msc(form.data, element)
        msc_data = fix_slug(msc_data, 'g')
        # TODO: apply logging and version control
        if element:
            # Existing record
            for key in element:
                organizations.update(delete(key), eids=[number])
            organizations.update(msc_data, eids=[number])
            flash('Successfully updated record.', 'success')
        else:
            # New record
            number = organizations.insert(msc_data)
            flash('Successfully added record.', 'success')
        return redirect(url_for('edit_organization', number=number))
    if form.errors:
        flash('Could not save changes as there {:/was an error/were N errors}. See below for details.'.format(Pluralizer(len(form.errors))), 'error')
    return render_template('edit-organization.html', form=form, eid=number,\
        idSchemes=id_scheme_list)

# Editing tools

class ToolForm(FlaskForm):
    schemes = db.table('metadata-schemes')
    scheme_choices = list()
    for scheme in schemes.all():
        scheme_choices.append( ('msc:m{}'.format(scheme.eid), scheme['title']) )
    scheme_choices.sort(key=lambda k: k[1].lower())
    organizations = db.table('organizations')
    organization_choices = list()
    for organization in organizations.all():
        organization_choices.append( ('msc:g{}'.format(organization.eid), organization['name']) )
    organization_choices.sort(key=lambda k: k[1].lower())

    title = StringField('Name of tool')
    description = TextAreaField('Description')
    supported_schemes = SelectMultipleField('Metadata scheme(s) supported by this tool', choices=scheme_choices)
    # Regex for types allowed for mappings
    allowed_types = r'(terminal \([^)]+\)|graphical \([^)]+\)|web service|web application|^$)'
    type_help = 'Must be one of "terminal (<platform>)", "graphical (<platform>)", "web service", "web application".'
    types = FieldList(StringField('Type', validators=[\
        validators.Regexp(allowed_types, message=type_help)]), 'Type of tool', min_entries=1)
    creators = FieldList(FormField(CreatorForm), 'People responsible for this tool', min_entries=1)
    maintainers = SelectMultipleField('Organizations that maintain this tool', choices=organization_choices)
    funders = SelectMultipleField('Organizations that funded this tool', choices=organization_choices)
    locations = FieldList(FormField(LocationForm), 'Links to this tool', min_entries=1)
    identifiers = FieldList(FormField(IdentifierForm), 'Identifiers for this tool', min_entries=1)
    versions = FieldList(FormField(VersionForm), 'Version history', min_entries=1)

@app.route('/edit/t<int:number>', methods=['GET', 'POST'])
def edit_tool(number):
    if g.user is None:
        flash('You must sign in before making any changes.', 'error')
        return redirect(url_for('login'))
    tools = db.table('tools')
    element = tools.get(eid=number)
    version = request.values.get('version')
    if version and request.referrer == request.base_url:
        # This is the version screen, opened from the main screen
        flash('Only provide information here that is different from the information in the main (non-version-specific) record.')
    type_list = ['web application', 'web service']
    for platform in computing_platforms:
        type_list.append('terminal ({})'.format(platform))
        type_list.append('graphical ({})'.format(platform))
    if element:
        # Translate from internal data model to form data
        if version:
            for release in element['versions']:
                if 'number' in release and str(release['number']) == str(version):
                    form = ToolForm(request.form, data=msc_to_form(release))
                    break
            else:
                form = ToolForm(request.form)
            del form['versions']
        else:
            form = ToolForm(request.form, data=msc_to_form(element))
    else:
        if number != 0:
            return redirect(url_for('edit_tool', number=0))
        form = ToolForm(request.form)
    for f in form.locations:
        f['type'].choices = [('', ''), ('document', 'document'), ('website', 'website'),\
            ('application', 'application'), ('service', 'service endpoint')]
    if request.method == 'POST' and form.validate():
        # TODO: apply logging and version control
        # Translate form data into internal data model
        msc_data = form_to_msc(form.data, element)
        if version:
            # Editing the version-specific overrides
            if element and 'versions' in element:
                version_list = element['versions']
                for index, item in enumerate(version_list):
                    if str(item['number']) == str(version):
                        version_dict = {k: v for k, v in item.items()\
                            if k in ['number', 'available', 'issued', 'valid']}
                        version_dict.update(msc_data)
                        version_list[index] = version_dict
                        Tool = Query()
                        Version = Query()
                        tools.update({'versions': version_list},\
                            Tool.versions.any(Version.number == version),\
                            eids=[number])
                        flash('Successfully updated record for version {}.'.format(version), 'success')
                        break
                else:
                    # This version is not in the list
                    flash('Could not apply changes. Have you saved details for version {} in the main record?'.format(version), 'error')
            else:
                # The version list or the main record is missing
                flash('Could not apply changes. Have you saved details for version {} in the main record?'.format(version), 'error')
            return redirect('{}?version={}'.format(url_for('edit_tool', number=number), version))
        elif element:
            # Editing an existing record
            msc_data = fix_slug(msc_data, 't')
            for key in element:
                tools.update(delete(key), eids=[number])
            tools.update(msc_data, eids=[number])
            flash('Successfully updated record.', 'success')
        else:
            # Adding a new record
            msc_data = fix_slug(msc_data, 't')
            number = tools.insert(msc_data)
            flash('Successfully added record.', 'success')
        return redirect(url_for('edit_tool', number=number))
    if form.errors:
        flash('Could not save changes as there {:/was an error/were N errors}. See below for details.'.format(Pluralizer(len(form.errors))), 'error')
    return render_template('edit-tool.html', form=form, eid=number,\
        version=version, idSchemes=id_scheme_list, toolTypes=type_list)

# Editing mappings

class MappingForm(FlaskForm):
    schemes = db.table('metadata-schemes')
    scheme_choices = list()
    for scheme in schemes.all():
        scheme_choices.append( ('msc:m{}'.format(scheme.eid), scheme['title']) )
    scheme_choices.sort(key=lambda k: k[1].lower())
    organizations = db.table('organizations')
    organization_choices = list()
    for organization in organizations.all():
        organization_choices.append( ('msc:g{}'.format(organization.eid), organization['name']) )
    organization_choices.sort(key=lambda k: k[1].lower())

    description = TextAreaField('Description')
    input_schemes = SelectMultipleField('Input metadata scheme(s)', choices=scheme_choices)
    output_schemes = SelectMultipleField('Output metadata scheme(s)', choices=scheme_choices)
    creators = FieldList(FormField(CreatorForm), 'People responsible for this mapping', min_entries=1)
    maintainers = SelectMultipleField('Organizations that maintain this mapping', choices=organization_choices)
    funders = SelectMultipleField('Organizations that funded this mapping', choices=organization_choices)
    locations = FieldList(FormField(FreeLocationForm), 'Links to this mapping', min_entries=1)
    identifiers = FieldList(FormField(IdentifierForm), 'Identifiers for this mapping', min_entries=1)
    versions = FieldList(FormField(VersionForm), 'Version history', min_entries=1)

@app.route('/edit/c<int:number>', methods=['GET', 'POST'])
def edit_mapping(number):
    if g.user is None:
        flash('You must sign in before making any changes.', 'error')
        return redirect(url_for('login'))
    mappings = db.table('mappings')
    element = mappings.get(eid=number)
    version = request.values.get('version')
    if version and request.referrer == request.base_url:
        # This is the version screen, opened from the main screen
        flash('Only provide information here that is different from the information in the main (non-version-specific) record.')
    location_type_list = ['document']
    for language in programming_languages:
        location_type_list.append('library ({})'.format(language))
    for platform in computing_platforms:
        location_type_list.append('executable ({})'.format(platform))
    if element:
        # Translate from internal data model to form data
        if version:
            for release in element['versions']:
                if 'number' in release and str(release['number']) == str(version):
                    form = MappingForm(request.form, data=msc_to_form(release))
                    break
            else:
                form = MappingForm(request.form)
            del form['versions']
        else:
            form = MappingForm(request.form, data=msc_to_form(element))
    else:
        if number != 0:
            return redirect(url_for('edit_mapping', number=0))
        form = MappingForm(request.form)
    if request.method == 'POST' and form.validate():
        # TODO: apply logging and version control
        # Translate form data into internal data model
        msc_data = form_to_msc(form.data, element)
        if version:
            # Editing the version-specific overrides
            if element and 'versions' in element:
                version_list = element['versions']
                for index, item in enumerate(version_list):
                    if str(item['number']) == str(version):
                        version_dict = {k: v for k, v in item.items()\
                            if k in ['number', 'available', 'issued', 'valid']}
                        version_dict.update(msc_data)
                        version_list[index] = version_dict
                        Mapping = Query()
                        Version = Query()
                        mappings.update({'versions': version_list},\
                            Mapping.versions.any(Version.number == version),\
                            eids=[number])
                        flash('Successfully updated record for version {}.'.format(version), 'success')
                        break
                else:
                    # This version is not in the list
                    flash('Could not apply changes. Have you saved details for version {} in the main record?'.format(version), 'error')
            else:
                # The version list or the main record is missing
                flash('Could not apply changes. Have you saved details for version {} in the main record?'.format(version), 'error')
            return redirect('{}?version={}'.format(url_for('edit_mapping', number=number), version))
        elif element:
            # Editing an existing record
            msc_data = fix_slug(msc_data, 'c')
            for key in element:
                mappings.update(delete(key), eids=[number])
            mappings.update(msc_data, eids=[number])
            flash('Successfully updated record.', 'success')
        else:
            # Adding a new record
            msc_data = fix_slug(msc_data, 'c')
            number = mappings.insert(msc_data)
            flash('Successfully added record.', 'success')
        return redirect(url_for('edit_mapping', number=number))
    if form.errors:
        flash('Could not save changes as there {:/was an error/were N errors}. See below for details.'.format(Pluralizer(len(form.errors))), 'error')
    return render_template('edit-mapping.html', form=form, eid=number,\
        version=version, idSchemes=id_scheme_list, locationTypes=location_type_list)

# Editing endorsements

class EndorsementForm(FlaskForm):
    organizations = db.table('organizations')
    organization_choices = list()
    for organization in organizations.all():
        organization_choices.append( ('msc:g{}'.format(organization.eid), organization['name']) )
    organization_choices.sort(key=lambda k: k[1].lower())

    citation = StringField('Citation')
    issued = NativeDateField('Endorsement date')
    valid_from = NativeDateField('Endorsement period')
    valid_to = NativeDateField('until')
    locations = FieldList(FormField(LocationForm), 'Links to this endorsement', min_entries=1)
    identifiers = FieldList(FormField(IdentifierForm), 'Identifiers for this endorsement', min_entries=1)
    endorsed_schemes = FieldList(FormField(SchemeVersionForm), 'Endorsed schemes', min_entries=1)
    originators = SelectMultipleField('Endorsing organizations', choices=organization_choices)

@app.route('/edit/e<int:number>', methods=['GET', 'POST'])
def edit_endorsement(number):
    if g.user is None:
        flash('You must sign in before making any changes.', 'error')
        return redirect(url_for('login'))
    endorsements = db.table('endorsements')
    element = endorsements.get(eid=number)
    if element:
        # Translate from internal data model to form data
        form = EndorsementForm(request.form, data=msc_to_form(element))
    else:
        if number != 0:
            return redirect(url_for('edit_endorsement', number=0))
        form = EndorsementForm(request.form)
    for f in form.locations:
        f['type'].choices = [('', ''), ('document', 'document')]
        f.url.validators = [validators.Optional()]
        f['type'].validators = [validators.Optional()]
    if request.method == 'POST' and form.validate():
        form_data = form.data
        filtered_locations = list()
        for f in form.locations:
            if f.url.data:
                location = {'url': f.url.data, 'type': 'document'}
                filtered_locations.append(location)
        form_data['locations'] = filtered_locations
        # Translate form data into internal data model
        msc_data = form_to_msc(form_data, element)
        msc_data = fix_slug(msc_data, 'e')
        # TODO: apply logging and version control
        if element:
            # Existing record
            for key in element:
                endorsements.update(delete(key), eids=[number])
            endorsements.update(msc_data, eids=[number])
            flash('Successfully updated record.', 'success')
        else:
            # New record
            number = endorsements.insert(msc_data)
            flash('Successfully added record.', 'success')
        return redirect(url_for('edit_endorsement', number=number))
    if form.errors:
        flash('Could not save changes as there {:/was an error/were N errors}. See below for details.'.format(Pluralizer(len(form.errors))), 'error')
    return render_template('edit-endorsement.html', form=form, eid=number,\
        idSchemes=id_scheme_list)

### Executing

if __name__ == '__main__':
    app.run(debug=True)
