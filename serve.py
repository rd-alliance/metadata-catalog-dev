#! /usr/bin/python3

# Dependencies
# ============

# Standard
# --------
import os
import sys
import re
import urllib
import json
import unicodedata

# Non-standard
# ------------
#
# See http://flask.pocoo.org/docs/0.10/
# On Debian, Ubuntu, etc.:
#   - old version: sudo apt-get install python3-flask
#   - latest version: sudo -H pip3 install flask
from flask import Flask, request, url_for, render_template, flash, redirect,\
    abort, jsonify, g, session

# See https://pythonhosted.org/Flask-OpenID/
# Install from PyPi: sudo -H pip3 install Flask-OpenID
from flask.ext.openid import OpenID

# See https://flask-wtf.readthedocs.io/en/stable/quickstart.html
# Install from PyPi: sudo -H pip3 install Flask-WTF
from flask_wtf import FlaskForm
from wtforms import validators, widgets, Form, FormField, FieldList,\
    StringField, TextAreaField, SelectField, SelectMultipleField, HiddenField,\
    ValidationError
from wtforms.compat import string_types

# See http://tinydb.readthedocs.io/
# Install from PyPi: sudo -H pip3 install tinydb
from tinydb import TinyDB, Query, where
from tinydb.database import Element
from tinydb.operations import delete
from tinydb.storages import Storage, touch

# See https://github.com/eugene-eeo/tinyrecord
# Install from PyPi: sudo -H pip3 install tinyrecord
from tinyrecord import transaction

# See http://rdflib.readthedocs.io/
# On Debian, Ubuntu, etc.:
#   - old version: sudo apt-get install python3-rdflib
#   - latest version: sudo -H pip3 install rdflib
import rdflib
from rdflib import Literal, Namespace
from rdflib.namespace import SKOS, RDF

# See https://www.dulwich.io/
# On Debian, Ubuntu, etc.:
#   - old version: sudo apt-get install python3-dulwich
#   - latest version: sudo -H pip3 install dulwich
from dulwich.repo import Repo
from dulwich.errors import NotGitRepository
import dulwich.porcelain as git


# Customization
# =============
mscwg_email = 'mscwg@rda-groups.org'


# New version of JSON storage that also stores changes in a Git repo
class JSONStorageWithGit(Storage):
    """Store the data in a JSON file and log the change in a Git repo.
    """

    def __init__(self, path, create_dirs=False, **kwargs):
        """Create a new instance.
        Also creates the storage file, if it doesn't exist.

        Arguments:
            path (str): Path/filename of the JSON data.
        """

        super(JSONStorageWithGit, self).__init__()
        # Create file if not exists
        touch(path, create_dirs=create_dirs)
        self.kwargs = kwargs
        self._handle = open(path, 'r+')
        # Ensure Git is configured properly
        git_repo = os.path.dirname(path)
        try:
            self.repo = Repo(git_repo)
        except NotGitRepository:
            self.repo = Repo.init(git_repo)
        self.filename = os.path.basename(path)
        self.name = os.path.splitext(self.filename)[0]

    @property
    def _refname(self):
        return b'refs/heads/master'

    def close(self):
        self._handle.close()

    def read(self):
        # Get the file size
        self._handle.seek(0, os.SEEK_END)
        size = self._handle.tell()

        if not size:
            # File is empty
            return None
        else:
            self._handle.seek(0)
            return json.load(self._handle)

    def write(self, data):
        # Write the json file
        self._handle.seek(0)
        serialized = json.dumps(data, **self.kwargs)
        self._handle.write(serialized)
        self._handle.flush()
        self._handle.truncate()

        # Add file to Git index
        git.add(repo=self.repo, paths=[self.filename])

        # Prepare commit information
        committer = 'MSCWG <{}>'.format(mscwg_email).encode('utf8')
        if g.user:
            author = ('{} <{}>'.format(g.user['name'], g.user['email'])
                      .encode('utf8'))
        else:
            author = committer
        if g.user:
            message = ('Update to {} from {}'
                       .format(self.name, g.user['name']).encode('utf8'))
        else:
            message = ('Update to {}'.format(self.name).encode('utf8'))

        # Execute commit
        git.commit(self.repo, message=message, author=author,
                   committer=committer)


# Basic setup
# ===========
app = Flask(__name__)
app.jinja_env.trim_blocks = True
app.jinja_env.lstrip_blocks = True

with open('key', 'r') as f:
    app.secret_key = f.read()

script_dir = os.path.dirname(sys.argv[0])
db_dir = os.path.join(script_dir, 'data')
db = TinyDB(os.path.realpath(os.path.join(db_dir, 'db.json')),
            storage=JSONStorageWithGit, sort_keys=True, indent=2,
            ensure_ascii=False)
user_db = TinyDB(os.path.realpath(os.path.join(db_dir, 'users.json')),
                 storage=JSONStorageWithGit, sort_keys=True, indent=2,
                 ensure_ascii=False)

thesaurus = rdflib.Graph()
thesaurus.parse('simple-unesco-thesaurus.ttl', format='turtle')
UNO = Namespace('http://vocabularies.unesco.org/ontology#')
thesaurus_link = ('<a href="http://vocabularies.unesco.org/browser/thesaurus/'
                  'en/">UNESCO Thesaurus</a>')

oid = OpenID(app, os.path.join(script_dir, 'open-id'))

# Data model
# ----------
table_names = {
    'm': 'metadata-schemes',
    'g': 'organizations',
    't': 'tools',
    'c': 'mappings',
    'e': 'endorsements'}

tables = dict()
for key, value in table_names.items():
    tables[key] = db.table(value)

templates = {
    'm': 'metadata-scheme.html',
    'g': 'organization.html',
    't': 'tool.html',
    'c': 'mapping.html',
    'e': 'endorsement.html'}

relations_msc_form = {
    'parent scheme': 'parent_schemes',
    'maintainer': 'maintainers',
    'funder': 'funders',
    'user': 'users',
    'supported scheme': 'supported_schemes',
    'input scheme': 'input_schemes',
    'output scheme': 'output_schemes',
    'endorsed scheme': 'endorsed_schemes',
    'originator': 'originators'}

relations_form_msc = {v: k for k, v in relations_msc_form.items()}

relations_inverse = {
    'parent scheme': 'child_schemes',
    'supported scheme': 'tools',
    'input scheme': 'mappings_from',
    'output scheme': 'mappings_to',
    'endorsed scheme': 'endorsements'}


# Utility functions
# =================
def request_wants_json():
    """Returns True if request is for JSON instead of HTML, False otherwise.

    From http://flask.pocoo.org/snippets/45/
    """
    best = request.accept_mimetypes \
        .best_match(['application/json', 'text/html'])
    return best == 'application/json' and \
        request.accept_mimetypes[best] > request.accept_mimetypes['text/html']


def get_term_list(uri, broader=True, narrower=True):
    """Recursively finds broader or narrower (or both) terms in the thesaurus.

    Arguments:
        uri (str): URI of term in thesaurus
        broader (Boolean): Whether to search for broader terms
            (default: True)
        narrower (Boolean): Whether to search for narrower terms
            (default: True)

    Returns:
        list: Given URI plus those of broader/narrower terms
    """
    terms = list()
    terms.append(uri)
    if broader:
        broader_terms = thesaurus.objects(uri, SKOS.broader)
        for broader_term in broader_terms:
            if broader_term not in terms:
                terms = get_term_list(broader_term, narrower=False) + terms
    if narrower:
        narrower_terms = thesaurus.objects(uri, SKOS.narrower)
        for narrower_term in narrower_terms:
            if narrower_term not in terms:
                terms += get_term_list(narrower_term, broader=False)
    return terms


def get_term_uri(term):
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


def get_term_tree(uris, filter=list()):
    """Takes a list of URIs of terms in the thesaurus and recursively builds
    a list of dictionaries, each of which providing the preferred label of
    the term in English, its corresponding URL in the Catalog, and (if
    applicable) a list of dictionaries corresponding to immediately narrower
    terms in the thesaurus.

    The list of narrower terms can optionally be filtered with a whitelist.

    Arguments:
        uris (list of str): List of URIs of terms in thesaurus
        filter (list): URIs of terms that can be listed as narrower than the
            given one

    Returns:
        list: Dictionaries of two or three items: 'name' (the preferred label
            of the term in English), 'url' (the URL of the corresponding
            Catalog page), 'children' (list of dictionaries, only present if
            narrower terms exist)
    """
    tree = list()
    for uri in uris:
        result = dict()
        term = str(thesaurus.preferredLabel(uri, lang='en')[0][1])
        result['name'] = term
        slug = to_url_slug(term)
        result['url'] = url_for('subject', subject=slug)
        narrower_ids = thesaurus.objects(uri, SKOS.narrower)
        children = list()
        if filter:
            children = [id for id in narrower_ids if id in filter]
        else:
            children = narrower_ids
        if children:
            result['children'] = get_term_tree(children, filter=filter)
        tree.append(result)
    tree.sort(key=lambda k: k['name'])
    return tree


def get_all_term_uris():
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
        uri = get_term_uri(keyword)
        if uri:
            keyword_uris.add(uri)
    # Get ancestor terms of all these
    full_keyword_uris = set()
    for keyword_uri in keyword_uris:
        if keyword_uri in full_keyword_uris:
            continue
        keyword_uri_list = get_term_list(keyword_uri, narrower=False)
        full_keyword_uris.update(keyword_uri_list)
    return full_keyword_uris


def get_db_tree(series, element_list):
    """Takes a list of database elements and recursively builds a list of
    dictionaries providing each element's title, its corresponding URL in the
    Catalog, and (if applicable) a list of elements that are 'children' of
    the current element.

    Arguments:
        series (str): Record series
        element_list (list of Elements): List of records

    Returns:
        list: List of dictionaries, each of which with two or three items:
        'name' (the title of the scheme or tool), 'url' (the URL of the
        corresponding Catalog page), 'children' (list of child schemes, only
        present if there are any)
    """
    tree = list()
    for element in element_list:
        result = dict()
        result['name'] = element['title']
        result['url'] = url_for('display', series=series, number=element.eid)
        if series == 'm':
            mscid = get_mscid(series, element.eid)
            Main = Query()
            Related = Query()
            children = tables[series].search(Main.relatedEntities.any(
                (Related.role == 'parent scheme') &
                (Related.id == mscid)))
            result['children'] = get_db_tree(series, children)
        tree.append(result)
    tree.sort(key=lambda k: k['name'].lower())
    return tree


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


def to_file_slug(string):
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


def to_url_slug(string):
    """Transforms string into URL-safe slug."""
    slug = urllib.parse.quote_plus(string)
    return slug


def from_url_slug(slug):
    """Transforms URL-safe slug back into regular string."""
    string = urllib.parse.unquote_plus(slug)
    return string


def wild_to_regex(string):
    """Transforms wildcard searches to regular expressions."""
    regex = re.escape(string)
    regex = regex.replace('\*', '.*')
    regex = regex.replace('\?', '.?')
    return regex


def parse_date_range(string):
    date_split = string.partition('/')
    if date_split[2]:
        return (date_split[0], date_split[2])
    return (string, None)


def EmailOrURL(form, field):
    """Raise error if URL/email address is not well-formed."""
    result = urllib.parse.urlparse(field.data)
    if result.scheme == 'mailto':
        if not re.match(r'[^@\s]+@[^@\s\.]+\.[^@\s]+', result.path):
            raise ValidationError(
                'That email address does not look quite right.')
    else:
        if not result.scheme:
            raise ValidationError(
                'Please provide the protocol (e.g. "http://", "mailto:").')
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
            raise Exception(
                'No field named "{}" in form'.format(self.other_field_name))
        if bool(other_field.data):
            self.field_flags = ('required', )
            if not field.raw_data or not field.raw_data[0]:
                if self.message is None:
                    message = field.gettext('This field is required.')
                else:
                    message = self.message
                field.errors[:] = []
                raise validators.StopValidation(message)
        elif (not field.raw_data) or (
                isinstance(field.raw_data[0], string_types) and
                not self.string_check(field.raw_data[0])):
            field.errors[:] = []
            raise validators.StopValidation()


w3cdate = re.compile(r'^\d{4}(-\d{2}){0,2}$')


def W3CDate(form, field):
    """Raise error if a string is not a valid W3C-formatted date."""
    if w3cdate.search(field.data) is None:
        raise ValidationError('Please provide the date in yyyy-mm-dd format.')


mscid_prefix = 'msc:'
mscid_format = re.compile(
    mscid_prefix
    + r'(?P<series>c|e|g|m|t)'
    + r'(?P<number>\d+)'
    + r'(#v(?P<version>.*))?$')


def parse_mscid(mscid):
    """Splits MSC ID into a series and a record EID number, returned as a
    tuple. If ID does not fit the pattern, return tuple of two None objects.
    """
    m = mscid_format.match(mscid)
    if m:
        return (m.group('series'), int(m.group('number')))
    return (None, None)


def get_mscid(series, number):
    """Forms an MSC ID from a series and a record EID number."""
    return mscid_prefix + series + number


def get_relation(mscid, element):
    """Looks within an element for a relation to a given entity (represented
    by MSC ID) and returns tuple where the first member is a role list and the
    second is an Element.

    Arguments:
        mscid (str): MSC ID of entity beign checked for
        element (Element): TinyDB element being checked

    Returns:
        tuple: First member is a role list (str) and the second is an Element
    """
    role_list = ''
    # We take a fresh copy so the adjustments we make don't accumulate
    record = Element(value=element.copy(), eid=element.eid)
    for entity in record['relatedEntities']:
        role = entity['role']
        if entity['id'] == mscid:
            if role in relations_inverse:
                role_list = relations_inverse[role]
        elif role in relations_msc_form:
            entity_series, entity_number = parse_mscid(entity['id'])
            role_type = relations_msc_form[role]
            if role_type not in record:
                record[role_type] = list()
            record[role_type].append(tables[entity_series]
                                     .get(eid=entity_number))
    if 'valid' in record:
        record['valid_from'], valid_until = parse_date_range(record['valid'])
        if valid_until:
            record['valid_until'] = valid_until
    return (role_list, record)


# Functions made available to templates
# -------------------------------------
@app.context_processor
def utility_processor():
    return {
        'toURLSlug': to_url_slug,
        'fromURLSlug': from_url_slug,
        'parseDateRange': parse_date_range}


# User handling
# =============
@app.before_request
def lookup_current_user():
    g.user = None
    if 'openid' in session:
        openid = session['openid']
        User = Query()
        g.user = user_db.get(User.openid == openid)


# Front page
# ==========
@app.route('/')
def hello():
    return render_template('home.html')


# Display record
# ==============
@app.route('/msc/<string(length=1):series><int:number>')
@app.route('/msc/<string(length=1):series><int:number>/<field>')
def display(series, number, field=None):
    # Is this record in the database?
    element = tables[series].get(eid=number)
    if not element:
        abort(404)

    # Form MSC ID
    mscid = 'msc:{}{}'.format(series, number)

    # Return raw JSON if requested.
    if request_wants_json():
        if 'identifiers' not in element:
            element['identifiers'] = list()
        element['identifiers'].insert(0, {
            'id': mscid,
            'scheme': 'RDA-MSCWG'})
        if field:
            if field in element:
                return jsonify({field: element[field]})
            else:
                return jsonify()
        else:
            return jsonify(element)

    # We only provide dedicated views for metadata schemes and tools
    if series not in ['m', 't']:
        flash('The URL you requested is part of the Catalog API and has no'
              ' HTML equivalent. <a href="mailto:{}">Let us know</a> if you'
              ' would find an HTML view of this record useful.'
              .format(mscwg_email), 'error')
        return redirect(url_for('hello'))

    # If the record has version information, interpret the associated dates.
    versions = None
    if 'versions' in element:
        versions = list()
        for v in element['versions']:
            if 'number' not in v:
                continue
            this_version = v
            this_version['status'] = ''
            if 'issued' in v:
                this_version['date'] = v['issued']
                if 'valid' in v:
                    date_range = parse_date_range(v['valid'])
                    if date_range[1]:
                        this_version['status'] = (
                            'deprecated on {}'.format(date_range[1]))
                    else:
                        this_version['status'] = 'current'
            elif 'valid' in v:
                date_range = parse_date_range(v['valid'])
                this_version['date'] = date_range[0]
                if date_range[1]:
                    this_version['status'] = (
                        'deprecated on {}'.format(date_range[1]))
                else:
                    this_version['status'] = 'current'
            elif 'available' in v:
                this_version['date'] = v['available']
                this_version['status'] = 'proposed'
            versions.append(this_version)
        try:
            versions.sort(key=lambda k: k['date'], reverse=True)
        except KeyError:
            print('WARNING: Record msc:{}{} has missing version date.'
                  .format(series, number))
            versions.sort(key=lambda k: k['number'], reverse=True)
        for version in versions:
            if version['status'] == 'current':
                break
            if version['status'] == 'proposed':
                continue
            if version['status'] == '':
                version['status'] = 'current'
                break

    # If the record has related entities, include the corresponding entries in
    # a 'relations' dictionary.
    relations = dict()
    hasRelatedSchemes = False
    if 'relatedEntities' in element:
        for entity in element['relatedEntities']:
            role = entity['role']
            if role not in relations_msc_form:
                print('WARNING: Record {} has related entity with unrecognized'
                      ' role "{}".'.format(mscid, role))
                continue
            relation_list = relations_msc_form[role]
            if relation_list not in relations:
                relations[relation_list] = list()
            entity_series, entity_number = parse_mscid(entity['id'])
            element_record = tables[entity_series].get(eid=entity_number)
            if element_record:
                relations[relation_list].append(element_record)
                if entity_series == 'm':
                    hasRelatedSchemes = True

    # Now we gather information about inverse relationships and add them to the
    # 'relations' dictionary as well.
    # For speed, we only run this check for metadata schemes, since only that
    # template currently includes this information.
    if series in ['m']:
        for s, t in tables.items():
            # The following query takes account of id#version syntax
            matches = t.search(Query().relatedEntities.any(
                Query()['id'].matches('{}(#v.*)?$'.format(mscid))))
            for match in matches:
                role_list, element_record = get_relation(mscid, match)
                if role_list:
                    if role_list in [
                            'child schemes', 'mappings_to', 'mappings_from']:
                        hasRelatedSchemes = True
                    if role_list not in relations:
                        relations[role_list] = list()
                    relations[role_list].append(element_record)

    # We are ready to display the information.
    return render_template(
        templates[series], record=element, versions=versions,
        relations=relations, hasRelatedSchemes=hasRelatedSchemes)


# Per-subject lists of standards
# ==============================
@app.route('/subject/<subject>')
def subject(subject):
    # If people start using geographical keywords, the following will need more
    # sophistication
    query_string = from_url_slug(subject)
    results = list()

    # Interpret subject
    term_list = list()
    if subject == 'Multidisciplinary':
        term_list.append('Multidisciplinary')
    else:
        # Translate term into concept ID
        concept_id = get_term_uri(query_string)
        if not concept_id:
            flash('The subject "{}" was not found in the {}.\n'.format(
                query_string, thesaurus_link), 'error')
            return render_template('search-results.html', title=query_string)
        # Find list of broader and narrower terms
        term_uri_list = get_term_list(concept_id)
        for term_uri in term_uri_list:
            term = str(thesaurus.preferredLabel(term_uri, lang='en')[0][1])
            if term not in term_list:
                term_list.append(term)

    # Search for matching schemes
    schemes = db.table('metadata-schemes')
    Scheme = Query()
    results = schemes.search(Scheme.keywords.any(term_list))
    no_of_hits = len(results)
    if no_of_hits:
        flash('Found {:N scheme/s}.'.format(Pluralizer(no_of_hits)))
        results.sort(key=lambda k: k['title'].lower())
    else:
        flash('Found 0 schemes.', 'error')
    return render_template(
        'search-results.html', title=query_string, results=results)


# Per-funder/maintainer lists of standards
# ========================================
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
    results = schemes.search(Scheme.relatedEntities.any(
        (Relation.role == role) & (Relation.id == 'msc:g{}'.format(id))))
    no_of_hits = len(results)
    if no_of_hits:
        flash('Found {:N scheme/s} {} by this organization.'.format(
            Pluralizer(no_of_hits), verb))
    else:
        flash('No schemes found {} by this organization.'.format(verb),
              'error')
    return render_template('search-results.html', title=title, results=results)


# Per-datatype lists of standards
# ===============================
@app.route('/datatype/<dataType>')
def dataType(dataType):
    query_string = from_url_slug(dataType)
    schemes = db.table('metadata-schemes')
    Scheme = Query()
    results = schemes.search(Scheme.dataTypes.any([query_string]))
    no_of_hits = len(results)
    if no_of_hits:
        flash('Found {:N scheme/s} used for this type of data.'.format(
            Pluralizer(no_of_hits)))
    else:
        flash('No schemes have been reported to be used for this type of'
              ' data.', 'error')
    return render_template(
        'search-results.html', title=query_string, results=results)


# List of standards
# =================
@app.route('/scheme-index')
def scheme_index():
    series = 'm'
    Scheme = Query()
    Entity = Query()
    matches = tables[series].search(Scheme.relatedEntities.all(
        Entity.role != 'parent scheme'))
    matches.extend(
        tables[series].search(~ Scheme.relatedEntities.exists()))
    tree = get_db_tree(series, matches)
    return render_template(
        'contents.html', title='List of metadata standards', tree=tree)


# List of tools
# =============
@app.route('/tool-index')
def tool_index():
    series = 't'
    matches = tables[series].all()
    tree = get_db_tree(series, matches)
    return render_template(
        'contents.html', title='List of metadata tools', tree=tree)


# Subject index
# =============
@app.route('/subject-index')
def subject_index():
    full_keyword_uris = get_all_term_uris()
    domains = thesaurus.subjects(RDF.type, UNO.Domain)
    subject_tree = get_term_tree(domains, filter=full_keyword_uris)
    subject_tree.insert(0, {
        'name': 'Multidisciplinary',
        'url': url_for('subject', subject='Multidisciplinary')})
    return render_template(
        'contents.html', title='Index of subjects', tree=subject_tree)


# Search form
# ===========
@app.route('/search', methods=['GET', 'POST'])
@app.route('/query/schemes', methods=['POST'])
def search():
    if request.method == 'POST':
        element_list = list()
        mscid_list = list()
        Scheme = Query()
        isGui = not request_wants_json()
        title = 'Search results'
        no_of_queries = 0

        if 'title' in request.form and request.form['title']:
            no_of_queries += 1
            title_query = wild_to_regex(request.form['title'])
            matches = tables['m'].search(Scheme.title.search(title_query))
            element_list, mscid_list = add_matches(
                matches, element_list, mscid_list)
            if isGui:
                flash_result(matches, 'with title "{}"'
                             .format(request.form['title']))

        concept_ids = set()
        term_set = set()
        if 'keyword' in request.form and request.form['keyword']:
            no_of_queries += 1
            if request.form['keyword'] == 'Multidisciplinary':
                # Use as is
                term_set.add('Multidisciplinary')
            else:
                # Translate term into concept ID
                concept_id = get_term_uri(request.form['keyword'])
                if concept_id:
                    concept_ids.add(concept_id)
                elif isGui:
                    flash('The subject "{}" was not found in the {}.\n'.format(
                        request.form['keyword'], thesaurus_link), 'error')
        if 'keyword-id' in request.form and request.form['keyword-id']:
            no_of_queries += 1
            concept_ids.add(request.form['keyword-id'])
        for concept_id in concept_ids:
            # - Find list of broader and narrower terms
            term_uri_list = get_term_list(concept_id)
            for term_uri in term_uri_list:
                term = str(
                    thesaurus.preferredLabel(term_uri, lang='en')[0][1])
                term_set.add(term)
        if term_set:
            # Search for matching schemes
            matches = tables['m'].search(Scheme.keywords.any(term_set))
            element_list, mscid_list = add_matches(
                matches, element_list, mscid_list)
            if isGui:
                flash_result(matches, 'related to {}'
                             .format(request.form['keyword']))

        if 'id' in request.form and request.form['id']:
            no_of_queries += 1
            matches = list()
            series, number = parse_mscid(request.form['id'])
            if (series == 'm') and number:
                matches.append(tables[series].get(eid=number))
            else:
                Identifier = Query()
                matches.extend(tables['m'].search(Scheme.identifiers.any(
                    Identifier.id == request.form['id'])))
            element_list, mscid_list = add_matches(
                matches, element_list, mscid_list)
            if isGui:
                flash_result(matches, 'with identifier "{}"'
                             .format(request.form['id']))

        if 'funder' in request.form and request.form['funder']:
            no_of_queries += 1
            # Interpret search
            Funder = Query()
            matching_funders = list()
            funder_query = wild_to_regex(request.form['funder'])
            funder_search = tables['g'].search(Funder.name.search(
                funder_query))
            for funder in funder_search:
                funder_mscid = get_mscid('g', funder.eid)
                matching_funders.append(funder_mscid)
            if matching_funders:
                Relation = Query()
                matches = list()
                for funder_mscid in matching_funders:
                    matches.extend(tables['m'].search(
                        Scheme.relatedEntities.any(
                            (Relation.role == 'funder') &
                            (Relation.id == funder_mscid))))
                element_list, mscid_list = add_matches(
                    matches, element_list, mscid_list)
                if isGui:
                    flash_result(matches, 'with funder "{}"'
                                 .format(request.form['funder']))
            elif isGui:
                flash('No funders found called "{}" .'.format(
                    request.form['funder']), 'error')

        if 'dataType' in request.form and request.form['dataType']:
            no_of_queries += 1
            matches = tables['m'].search(Scheme.dataTypes.any(
                [request.form['dataType']]))
            element_list, mscid_list = add_matches(
                matches, element_list, mscid_list)
            if isGui:
                flash_result(matches, 'associated with {}'
                             .format(request.form['dataType']))

        # Show results
        if isGui:
            no_of_hits = len(element_list)
            if no_of_queries > 1:
                flash('Found {:N scheme/s} in total. '.format(
                    Pluralizer(no_of_hits)))
            if no_of_hits == 1:
                # Go direct to that page
                result = element_list.pop()
                return redirect(url_for('scheme', number=result.eid))
            # Otherwise return as a list
            element_list.sort(key=lambda k: k['title'].lower())
            # Show results list
            return render_template(
                'search-results.html', title=title, results=element_list)
        else:
            n = len(mscid_prefix) + 1
            mscid_list.sort(key=lambda k: k[:n] + k[n:].zfill(5))
            return jsonify({'ids': mscid_list})

    else:
        # Title, identifier, funder, dataType help
        all_schemes = tables['m'].all()
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
                        funder = tables['g'].get(eid=int(org_id[5:]))
                        if funder:
                            funder_set.add(funder['name'])
                        else:
                            print('Could not look up organization with eid {}.'
                                  .format(org_id[5:]))
        title_list = list(title_set)
        title_list.sort(key=lambda k: k.lower())
        id_list = list(id_set)
        id_list.sort()
        funder_list = list(funder_set)
        funder_list.sort(key=lambda k: k.lower())
        type_list = list(type_set)
        type_list.sort(key=lambda k: k.lower())
        # Subject help
        full_keyword_uris = get_all_term_uris()
        subject_set = set()
        for uri in full_keyword_uris:
            subject_set.add(str(
                thesaurus.preferredLabel(uri, lang='en')[0][1]))
        subject_set.add('Multidisciplinary')
        subject_list = list(subject_set)
        subject_list.sort()
        return render_template(
            'search-form.html', titles=title_list, subjects=subject_list,
            ids=id_list, funders=funder_list, dataTypes=type_list)


def add_matches(matches, element_list, mscid_list):
    """Scans list of database elements and adds them to a given list of
    elements and a given list of EIDs, but only if they are not already
    there.

    Arguments:
        matches (list of Elements): New list of records
        element_list (list of Elements): Existing list of records
        eid_list (list of str): Existing list of MSC IDs

    Returns:
        tuple: list of records and list of EIDs
    """
    for element in matches:
        mscid = get_mscid('m', element.eid)
        if mscid not in mscid_list:
            element_list.append(element)
            mscid_list.append(mscid)
    return (element_list, mscid_list)


def flash_result(matches, type):
    """Flashes user with informative message about a search result, based on
    thing they are supposed to have in common.

    Arguments:
        matches (list of Elements): List of records
        type (str): Basis of matching, e.g. 'with title X'
    """
    no_of_hits = len(matches)
    if no_of_hits:
        flash('Found {:N scheme/s} {}.'.format(Pluralizer(no_of_hits), type))
    else:
        flash('No schemes found {}. '.format(type), 'error')
    return None


# User login
# ==========
@app.route('/login', methods=['GET', 'POST'])
@oid.loginhandler
def login():
    if g.user is not None:
        return redirect(oid.get_next_url())
    if request.method == 'POST':
        openid = request.form.get('openid')
        if openid:
            return oid.try_login(
                openid, ask_for=['email', 'nickname'],
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
    return redirect(url_for(
        'create_profile', next=oid.get_next_url(),
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
            user_db.insert({
                'name': name, 'email': email, 'openid': session['openid']})
            flash('Profile successfully created.')
            return redirect(oid.get_next_url())
    return render_template('create-profile.html', next=oid.get_next_url())


@app.route('/logout')
def logout():
    session.pop('openid', None)
    flash('You were signed out')
    return redirect(oid.get_next_url())


# Editing screens
# ===============
#
# Utility functions for WTForms implementation
# --------------------------------------------
def clean_dict(data):
    """Takes dictionary and recursively removes fields where the value is (a)
    an empty string, (b) an empty list, (c) a dictionary wherein all the values
    are empty, (d) null. Values of 0 are not removed.
    """
    for key, value in data.copy().items():
        if isinstance(value, dict):
            new_value = clean_dict(value)
            if not new_value:
                del data[key]
            else:
                data[key] = new_value
        elif isinstance(value, list):
            if not value:
                del data[key]
            else:
                clean_list = list()
                for item in value:
                    if isinstance(item, dict):
                        new_item = clean_dict(item)
                        if new_item:
                            clean_list.append(new_item)
                    elif item:
                        clean_list.append(item)
                if clean_list:
                    data[key] = clean_list
                else:
                    del data[key]
        elif value == '':
            del data[key]
        elif value is None:
            del data[key]
        elif key is 'csrf_token':
            del data[key]
    return data


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
                    form_data[mapped_role].append({
                        'id': id_tuple[0], 'version': id_tuple[2]})
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
        form_data['locations'].append({'url': '', 'type': ''})
    if 'identifiers' in form_data:
        form_data['identifiers'].append({'id': '', 'scheme': ''})
    if 'versions' in form_data:
        form_data['versions'].append({'number': '', 'issued': ''})
    if 'creators' in form_data:
        form_data['creators'].append({
            'fullName': '', 'givenName': '', 'familyName': ''})
    if 'endorsed_schemes' in form_data:
        form_data['endorsed_schemes'].append({'id': '', 'version': ''})
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
                        id_string = '{}#v{}'.format(
                            item['id'], item['version'])
                    else:
                        id_string = item['id']
                else:
                    id_string = item
                msc_data['relatedEntities'].append({
                    'id': id_string, 'role': role})
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
                                if 'number' in release and\
                                        str(release['number']) == str(value):
                                    overrides = {
                                        i: j for i, j in release.items()
                                        if i not in [
                                            'number', 'available', 'issued',
                                            'valid']}
                                    mapped_version.update(overrides)
                                    break
                    else:
                        mapped_version[key] = value
                if has_vn_valid_from:
                    if has_vn_valid_to:
                        mapped_version['valid'] = '{}/{}'.format(
                            version['valid_from'], version['valid_to'])
                    else:
                        mapped_version['valid'] = version['valid_from']
                msc_data[k].append(mapped_version)
        elif k in ['keywords', 'dataTypes']:
            term_set = set()
            for term in v:
                term_set.add(term)
            terms = list(term_set)
            terms.sort()
            msc_data[k] = terms
        else:
            msc_data[k] = v
        if has_tl_valid_from:
            if has_tl_valid_to:
                msc_data['valid'] = '{}/{}'.format(
                    clean_data['valid_from'], clean_data['valid_to'])
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
    slug = None
    if series == 'm' or series == 't':
        if 'title' in record:
            slug = to_file_slug(record['title'])
    elif series == 'g':
        if 'name' in record:
            slug = to_file_slug(record['title'])
    elif series == 'e':
        if 'citation' in record:
            slug = to_file_slug(record['citation'])
    elif series == 'c':
        if 'relatedEntities' in record:
            slug_from = ''
            slug_to = ''
            schemes = db.table(table_names['m'])
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
        raise Exception('Unrecognized record series "{}"; cannot fix slug.'
                        .format(series))
    # Exit if this didn't work
    if not slug:
        return record
    # Ensure uniqueness then apply
    table = db.table(table_names[series])
    i = ''
    while table.search(Query().slug == (slug + str(i))):
        if i == '':
            i = 1
        else:
            i += 1
    else:
        record['slug'] = slug
    return record


computing_platforms = ['Windows', 'Mac OS X', 'Linux', 'BSD', 'cross-platform']

# Top 10 languages according to http://www.langpop.com/ in 2013.
# Though not really belonging here, 'XML' added for XSL tranformations.
programming_languages = [
    'C', 'Java', 'PHP', 'JavaScript', 'C++', 'Python', 'Shell', 'Ruby',
    'Objective-C', 'C#', 'XML']
programming_languages.sort()

id_scheme_list = ['DOI']


# Common form snippets
# --------------------
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
    type_help = ('Must be one of "document", "library (<language>)",'
                 ' "executable (<platform>)".')
    type = StringField('Type', validators=[
        RequiredIf('url'),
        validators.Regexp(allowed_locations, message=type_help)])


class SampleForm(Form):
    title = StringField('Title', validators=[RequiredIf('url')])
    url = StringField('URL', validators=[RequiredIf('title'), EmailOrURL])


class IdentifierForm(Form):
    id = StringField('ID')
    scheme = StringField('ID scheme')


class VersionForm(Form):
    number = StringField('Version number', validators=[
        RequiredIf('issued'), RequiredIf('available'),
        RequiredIf('valid_from'), validators.Length(max=20)])
    number_old = HiddenField(validators=[validators.Length(max=20)])
    issued = NativeDateField('Date published')
    available = NativeDateField('Date released as draft/proposal')
    valid_from = NativeDateField('Date considered current')
    valid_to = NativeDateField('until')


class SchemeVersionForm(Form):
    schemes = db.table('metadata-schemes')
    scheme_choices = [('', '')]
    for scheme in schemes.all():
        if 'title' in scheme:
            scheme_choices.append(
                ('msc:m{}'.format(scheme.eid), scheme['title']))
        else:
            print('WARNING: msc:m{} has no title.'.format(scheme.eid))
    scheme_choices.sort(key=lambda k: k[1].lower())

    id = SelectField('Metadata scheme', choices=scheme_choices)
    version = StringField('Version')


class CreatorForm(Form):
    fullName = StringField('Full name')
    givenName = StringField('Given name(s)')
    familyName = StringField('Family name')


# Editing metadata schemes
# ------------------------
class SchemeForm(FlaskForm):
    schemes = db.table('metadata-schemes')
    scheme_choices = list()
    for scheme in schemes.all():
        if 'title' in scheme:
            scheme_choices.append(
                ('msc:m{}'.format(scheme.eid), scheme['title']))
        else:
            print('WARNING: msc:m{} has no title.'.format(scheme.eid))
    scheme_choices.sort(key=lambda k: k[1].lower())
    organizations = db.table('organizations')
    organization_choices = list()
    for organization in organizations.all():
        organization_choices.append((
            'msc:g{}'.format(organization.eid), organization['name']))
    organization_choices.sort(key=lambda k: k[1].lower())

    title = StringField('Name of metadata scheme')
    description = TextAreaField('Description')
    keywords = FieldList(
        StringField('Subject area'), 'Subject areas', min_entries=1)
    dataTypes = FieldList(
        StringField('URL or term'), 'Data types', min_entries=1)
    parent_schemes = SelectMultipleField(
        'Parent metadata scheme(s)', choices=scheme_choices)
    maintainers = SelectMultipleField(
        'Organizations that maintain this scheme',
        choices=organization_choices)
    funders = SelectMultipleField(
        'Organizations that funded this scheme', choices=organization_choices)
    users = SelectMultipleField(
        'Organizations that use this scheme', choices=organization_choices)
    locations = FieldList(
        FormField(LocationForm), 'Relevant links', min_entries=1)
    samples = FieldList(
        FormField(SampleForm), 'Sample records conforming to this scheme',
        min_entries=1)
    identifiers = FieldList(
        FormField(IdentifierForm), 'Identifiers for this scheme',
        min_entries=1)
    versions = FieldList(
        FormField(VersionForm), 'Version history', min_entries=1)


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
        flash('Only provide information here that is different from the'
              ' information in the main (non-version-specific) record.')
    # Subject help
    all_keyword_uris = set()
    for generator in [
            thesaurus.subjects(RDF.type, UNO.Domain),
            thesaurus.subjects(RDF.type, UNO.MicroThesaurus),
            thesaurus.subjects(RDF.type, SKOS.Concept)]:
        for uri in generator:
            all_keyword_uris.add(uri)
    subject_set = set()
    for uri in all_keyword_uris:
        subject_set.add(str(thesaurus.preferredLabel(uri, lang='en')[0][1]))
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
                if 'number' in release and\
                        str(release['number']) == str(version):
                    form = SchemeForm(request.form, data=msc_to_form(release))
                    break
            else:
                form = SchemeForm(request.form)
            del form['versions']
        else:
            form = SchemeForm(request.form, data=msc_to_form(element))
    else:
        #if number != 0:
            #return redirect(url_for('edit_scheme', number=0))
        form = SchemeForm(request.form)
    for f in form.locations:
        f['type'].choices = [
            ('', ''), ('document', 'document'), ('website', 'website'),
            ('RDA-MIG', 'RDA MIG Schema'), ('DTD', 'XML/SGML DTD'),
            ('XSD', 'XML Schema'), ('RDFS', 'RDF Schema')]
    for f in form.keywords:
        f.validators = [validators.Optional(), validators.AnyOf(
            subject_list, 'Value must match an English preferred label in the'
            ' {}.'.format(thesaurus_link))]
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
                        version_dict = {
                            k: v for k, v in item.items()
                            if k in ['number', 'available', 'issued', 'valid']}
                        version_dict.update(msc_data)
                        version_list[index] = version_dict
                        Scheme = Query()
                        Version = Query()
                        schemes.update(
                            {'versions': version_list},
                            Scheme.versions.any(Version.number == version),
                            eids=[number])
                        flash('Successfully updated record for version {}.'
                              .format(version), 'success')
                        break
                else:
                    # This version is not in the list
                    flash('Could not apply changes. Have you saved details for'
                          ' version {} in the main record?'.format(version),
                          'error')
            else:
                # The version list or the main record is missing
                flash('Could not apply changes. Have you saved details for'
                      ' version {} in the main record?'.format(version),
                      'error')
            return redirect('{}?version={}'.format(url_for(
                'edit_scheme', number=number), version))
        elif element:
            # Editing an existing record
            msc_data = fix_slug(msc_data, 'm')
            with transaction(schemes) as t:
                for key in (k for k in element if k not in msc_data):
                    t.update(delete(key), eids=[number])
                t.update(msc_data, eids=[number])
            flash('Successfully updated record.', 'success')
        else:
            # Adding a new record
            msc_data = fix_slug(msc_data, 'm')
            number = schemes.insert(msc_data)
            flash('Successfully added record.', 'success')
        return redirect(url_for('edit_scheme', number=number))
    if form.errors:
        flash('Could not save changes as there {:/was an error/were N errors}.'
              ' See below for details.'.format(Pluralizer(len(form.errors))),
              'error')
    return render_template(
        'edit-scheme.html', form=form, eid=number, version=version,
        subjects=subject_list, dataTypes=type_list, idSchemes=id_scheme_list)


# Editing organizations
# ---------------------
class OrganizationForm(FlaskForm):
    organization_choices = [
            ('standards body', 'standards body'), ('archive', 'archive'),
            ('professional group', 'professional group'),
            ('coordination group', 'coordination group')]

    name = StringField('Name of organization')
    description = TextAreaField('Description')
    types = SelectMultipleField(
        'Type of organization', choices=organization_choices)
    locations = FieldList(
        FormField(LocationForm), 'Relevant links', min_entries=1)
    identifiers = FieldList(
        FormField(IdentifierForm), 'Identifiers for this organization',
        min_entries=1)


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
        f['type'].choices = [
            ('', ''), ('website', 'website'), ('email', 'email address')]
    # Processing the request
    if request.method == 'POST' and form.validate():
        # Translate form data into internal data model
        msc_data = form_to_msc(form.data, element)
        msc_data = fix_slug(msc_data, 'g')
        # TODO: apply logging and version control
        if element:
            # Existing record
            with transaction(organizations) as t:
                for key in (k for k in element if k not in msc_data):
                    t.update(delete(key), eids=[number])
                t.update(msc_data, eids=[number])
            flash('Successfully updated record.', 'success')
        else:
            # New record
            number = organizations.insert(msc_data)
            flash('Successfully added record.', 'success')
        return redirect(url_for('edit_organization', number=number))
    if form.errors:
        flash('Could not save changes as there {:/was an error/were N errors}.'
              ' See below for details.'.format(Pluralizer(len(form.errors))),
              'error')
    return render_template(
        'edit-organization.html', form=form, eid=number,
        idSchemes=id_scheme_list)


# Editing tools
# -------------
class ToolForm(FlaskForm):
    schemes = db.table('metadata-schemes')
    scheme_choices = list()
    for scheme in schemes.all():
        if 'title' in scheme:
            scheme_choices.append(
                ('msc:m{}'.format(scheme.eid), scheme['title']))
        else:
            print('WARNING: msc:m{} has no title.'.format(scheme.eid))
    scheme_choices.sort(key=lambda k: k[1].lower())
    organizations = db.table('organizations')
    organization_choices = list()
    for organization in organizations.all():
        organization_choices.append((
            'msc:g{}'.format(organization.eid), organization['name']))
    organization_choices.sort(key=lambda k: k[1].lower())

    title = StringField('Name of tool')
    description = TextAreaField('Description')
    supported_schemes = SelectMultipleField(
        'Metadata scheme(s) supported by this tool', choices=scheme_choices)
    # Regex for types allowed for mappings
    allowed_types = (r'(terminal \([^)]+\)|graphical \([^)]+\)|web service|'
                     'web application|^$)')
    type_help = ('Must be one of "terminal (<platform>)", "graphical'
                 ' (<platform>)", "web service", "web application".')
    types = FieldList(
        StringField('Type', validators=[
            validators.Regexp(allowed_types, message=type_help)]),
        'Type of tool', min_entries=1)
    creators = FieldList(
        FormField(CreatorForm), 'People responsible for this tool',
        min_entries=1)
    maintainers = SelectMultipleField(
        'Organizations that maintain this tool', choices=organization_choices)
    funders = SelectMultipleField(
        'Organizations that funded this tool', choices=organization_choices)
    locations = FieldList(
        FormField(LocationForm), 'Links to this tool', min_entries=1)
    identifiers = FieldList(
        FormField(IdentifierForm), 'Identifiers for this tool', min_entries=1)
    versions = FieldList(
        FormField(VersionForm), 'Version history', min_entries=1)


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
        flash('Only provide information here that is different from the'
              ' information in the main (non-version-specific) record.')
    type_list = ['web application', 'web service']
    for platform in computing_platforms:
        type_list.append('terminal ({})'.format(platform))
        type_list.append('graphical ({})'.format(platform))
    if element:
        # Translate from internal data model to form data
        if version:
            for release in element['versions']:
                if 'number' in release and\
                        str(release['number']) == str(version):
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
        f['type'].choices = [
            ('', ''), ('document', 'document'), ('website', 'website'),
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
                        version_dict = {
                            k: v for k, v in item.items()
                            if k in ['number', 'available', 'issued', 'valid']}
                        version_dict.update(msc_data)
                        version_list[index] = version_dict
                        Tool = Query()
                        Version = Query()
                        tools.update(
                            {'versions': version_list},
                            Tool.versions.any(Version.number == version),
                            eids=[number])
                        flash('Successfully updated record for version {}.'
                              .format(version), 'success')
                        break
                else:
                    # This version is not in the list
                    flash('Could not apply changes. Have you saved details for'
                          ' version {} in the main record?'.format(version),
                          'error')
            else:
                # The version list or the main record is missing
                flash('Could not apply changes. Have you saved details for'
                      ' version {} in the main record?'.format(version),
                      'error')
            return redirect('{}?version={}'.format(
                url_for('edit_tool', number=number), version))
        elif element:
            # Editing an existing record
            msc_data = fix_slug(msc_data, 't')
            with transaction(tools) as t:
                for key in (k for k in element if k not in msc_data):
                    t.update(delete(key), eids=[number])
                t.update(msc_data, eids=[number])
            flash('Successfully updated record.', 'success')
        else:
            # Adding a new record
            msc_data = fix_slug(msc_data, 't')
            number = tools.insert(msc_data)
            flash('Successfully added record.', 'success')
        return redirect(url_for('edit_tool', number=number))
    if form.errors:
        flash('Could not save changes as there {:/was an error/were N errors}.'
              ' See below for details.'.format(Pluralizer(len(form.errors))),
              'error')
    return render_template(
        'edit-tool.html', form=form, eid=number, version=version,
        idSchemes=id_scheme_list, toolTypes=type_list)


# Editing mappings
# ----------------
class MappingForm(FlaskForm):
    schemes = db.table('metadata-schemes')
    scheme_choices = list()
    for scheme in schemes.all():
        if 'title' in scheme:
            scheme_choices.append(
                ('msc:m{}'.format(scheme.eid), scheme['title']))
        else:
            print('WARNING: msc:m{} has no title.'.format(scheme.eid))
    scheme_choices.sort(key=lambda k: k[1].lower())
    organizations = db.table('organizations')
    organization_choices = list()
    for organization in organizations.all():
        organization_choices.append((
            'msc:g{}'.format(organization.eid), organization['name']))
    organization_choices.sort(key=lambda k: k[1].lower())

    description = TextAreaField('Description')
    input_schemes = SelectMultipleField(
        'Input metadata scheme(s)', choices=scheme_choices)
    output_schemes = SelectMultipleField(
        'Output metadata scheme(s)', choices=scheme_choices)
    creators = FieldList(
        FormField(CreatorForm), 'People responsible for this mapping',
        min_entries=1)
    maintainers = SelectMultipleField(
        'Organizations that maintain this mapping',
        choices=organization_choices)
    funders = SelectMultipleField(
        'Organizations that funded this mapping', choices=organization_choices)
    locations = FieldList(
        FormField(FreeLocationForm), 'Links to this mapping', min_entries=1)
    identifiers = FieldList(
        FormField(IdentifierForm), 'Identifiers for this mapping',
        min_entries=1)
    versions = FieldList(
        FormField(VersionForm), 'Version history', min_entries=1)


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
        flash('Only provide information here that is different from the'
              ' information in the main (non-version-specific) record.')
    location_type_list = ['document']
    for language in programming_languages:
        location_type_list.append('library ({})'.format(language))
    for platform in computing_platforms:
        location_type_list.append('executable ({})'.format(platform))
    if element:
        # Translate from internal data model to form data
        if version:
            for release in element['versions']:
                if 'number' in release and\
                        str(release['number']) == str(version):
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
                        version_dict = {
                            k: v for k, v in item.items()
                            if k in ['number', 'available', 'issued', 'valid']}
                        version_dict.update(msc_data)
                        version_list[index] = version_dict
                        Mapping = Query()
                        Version = Query()
                        mappings.update(
                            {'versions': version_list},
                            Mapping.versions.any(Version.number == version),
                            eids=[number])
                        flash('Successfully updated record for version {}.'
                              .format(version), 'success')
                        break
                else:
                    # This version is not in the list
                    flash('Could not apply changes. Have you saved details for'
                          ' version {} in the main record?'.format(version),
                          'error')
            else:
                # The version list or the main record is missing
                flash('Could not apply changes. Have you saved details for'
                      ' version {} in the main record?'.format(version),
                      'error')
            return redirect('{}?version={}'.format(
                url_for('edit_mapping', number=number), version))
        elif element:
            # Editing an existing record
            msc_data = fix_slug(msc_data, 'c')
            with transaction(mappings) as t:
                for key in (k for k in element if k not in msc_data):
                    t.update(delete(key), eids=[number])
                t.update(msc_data, eids=[number])
            flash('Successfully updated record.', 'success')
        else:
            # Adding a new record
            msc_data = fix_slug(msc_data, 'c')
            number = mappings.insert(msc_data)
            flash('Successfully added record.', 'success')
        return redirect(url_for('edit_mapping', number=number))
    if form.errors:
        flash('Could not save changes as there {:/was an error/were N errors}.'
              ' See below for details.'.format(Pluralizer(len(form.errors))),
              'error')
    return render_template(
        'edit-mapping.html', form=form, eid=number, version=version,
        idSchemes=id_scheme_list, locationTypes=location_type_list)


# Editing endorsements
# --------------------
class EndorsementForm(FlaskForm):
    organizations = db.table('organizations')
    organization_choices = list()
    for organization in organizations.all():
        organization_choices.append((
            'msc:g{}'.format(organization.eid), organization['name']))
    organization_choices.sort(key=lambda k: k[1].lower())

    citation = StringField('Citation')
    issued = NativeDateField('Endorsement date')
    valid_from = NativeDateField('Endorsement period')
    valid_to = NativeDateField('until')
    locations = FieldList(
        FormField(LocationForm), 'Links to this endorsement', min_entries=1)
    identifiers = FieldList(
        FormField(IdentifierForm), 'Identifiers for this endorsement',
        min_entries=1)
    endorsed_schemes = FieldList(
        FormField(SchemeVersionForm), 'Endorsed schemes', min_entries=1)
    originators = SelectMultipleField(
        'Endorsing organizations', choices=organization_choices)


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
            with transaction(endorsements) as t:
                for key in (k for k in element if k not in msc_data):
                    t.update(delete(key), eids=[number])
                t.update(msc_data, eids=[number])
            flash('Successfully updated record.', 'success')
        else:
            # New record
            number = endorsements.insert(msc_data)
            flash('Successfully added record.', 'success')
        return redirect(url_for('edit_endorsement', number=number))
    if form.errors:
        flash('Could not save changes as there {:/was an error/were N errors}.'
              ' See below for details.'.format(Pluralizer(len(form.errors))),
              'error')
    return render_template(
        'edit-endorsement.html', form=form, eid=number,
        idSchemes=id_scheme_list)


# Executing
# =========
if __name__ == '__main__':
    app.run(debug=True)
