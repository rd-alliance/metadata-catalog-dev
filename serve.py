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
import html
import subprocess
from datetime import datetime, timezone
from email.utils import parsedate_tz, mktime_tz

# Non-standard
# ------------
#
# See http://flask.pocoo.org/docs/0.10/
# On Debian, Ubuntu, etc.:
#   - old version: sudo apt-get install python3-flask
#   - latest version: sudo -H pip3 install flask
from flask import Flask, request, url_for, render_template, flash, redirect,\
    abort, jsonify, g, session
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)
from werkzeug.datastructures import MultiDict

# See https://flask-login.readthedocs.io/
# Install from PyPi: sudo -H pip3 install flask-login
from flask_login import LoginManager, UserMixin, login_user, logout_user,\
    current_user, login_required

# See https://rauth.readthedocs.io/
# Install form PyPi: sudo -H pip3 install rauth
from rauth import OAuth1Service, OAuth2Service
import requests

# See https://developers.google.com/api-client-library/python/guide/aaa_oauth
# Install form PyPi: sudo -H pip3 install oauth2client
from oauth2client import client, crypt

# See https://pythonhosted.org/Flask-OpenID/
# Install from PyPi: sudo -H pip3 install Flask-OpenID
from flask_openid import OpenID

# See https://flask-httpauth.readthedocs.io/
# Install from PyPi: sudo -H pip3 install flask-httpauth
from flask_httpauth import HTTPBasicAuth

# See https://passlib.readthedocs.io/
# Install from PyPi: sudo -H pip3 install passlib
from passlib.apps import custom_app_context as pwd_context

# See https://flask-wtf.readthedocs.io/ and https://wtforms.readthedocs.io/
# Install from PyPi: sudo -H pip3 install Flask-WTF
from flask_wtf import FlaskForm
from wtforms import validators, widgets, Form, FormField, FieldList,\
    StringField, TextAreaField, SelectField, SelectMultipleField, HiddenField,\
    ValidationError
from wtforms.compat import string_types

# See http://tinydb.readthedocs.io/
# Install from PyPi: sudo -H pip3 install tinydb
from tinydb import TinyDB, Query, where
from tinydb.database import Document
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


# See https://github.com/bloomberg/python-github-webhook
# Installed locally
from github_webhook import Webhook
# need to allow CORS for requests from js
from flask_cors import CORS, cross_origin

# Customization
# =============
mscwg_email = 'mscwg@rda-groups.org'


# Replacement for JSONStorage
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
        self.filename = path
        basename = os.path.basename(path)
        self.name = os.path.splitext(basename)[0]

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
        # This will either catch an API user or return None
        user = g.get('user', None)
        if current_user.is_authenticated:
            # If human user is logged in, use their record instead
            user = current_user
        if user:
            author = ('{} <{}>'.format(
                user['name'], user['email']).encode('utf8'))
            message = ('Update to {} from {}\n\nUser ID:\n{}'.format(
                self.name, user['name'], user['userid'])
                .encode('utf8'))
        else:
            author = committer
            message = ('Update to {}'.format(self.name).encode('utf8'))

        # Execute commit
        git.commit(self.repo, message=message, author=author,
                   committer=committer)


class User(Document):
    '''This provides implementations for the methods that Flask-Login
    expects user objects to have.
    '''
    __hash__ = Document.__hash__

    @property
    def is_active(self):
        if self.get('blocked'):
            return False
        return True

    @property
    def is_authenticated(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.doc_id)

    def __eq__(self, other):
        '''
        Checks the equality of two `UserMixin` objects using `get_id`.
        '''
        if isinstance(other, User):
            return self.get_id() == other.get_id()
        return NotImplemented

    def __ne__(self, other):
        '''
        Checks the inequality of two `UserMixin` objects using `get_id`.
        '''
        equal = self.__eq__(other)
        if equal is NotImplemented:
            return NotImplemented
        return not equal


class OAuthSignIn(object):
    '''Abstraction layer for RAuth. Source:
    https://blog.miguelgrinberg.com/post/oauth-authentication-with-flask
    '''
    providers = None

    def __init__(self, provider_name):
        self.provider_name = provider_name
        if 'OAUTH_CREDENTIALS' not in app.config:
            print('WARNING: OAuth authentication will not work without secret'
                  ' application keys. Please run your tests with a different'
                  ' authentication method.')
            self.consumer_id = None
            self.consumer_secret = None
        else:
            credentials = app.config['OAUTH_CREDENTIALS'][provider_name]
            self.consumer_id = credentials['id']
            self.consumer_secret = credentials['secret']

    def authorize(self):
        pass

    def callback(self):
        pass

    def get_callback_url(self):
        return url_for('oauth_callback', provider=self.provider_name,
                       _external=True)

    @classmethod
    def get_provider(self, provider_name):
        if self.providers is None:
            self.providers = {}
            for provider_class in self.__subclasses__():
                provider = provider_class()
                self.providers[provider.provider_name] = provider
        return self.providers[provider_name]


class GoogleSignIn(OAuthSignIn):
    def __init__(self):
        super(GoogleSignIn, self).__init__('google')
        self.formatted_name = 'Google'
        discovery = oauth_db.get(Query().provider == self.provider_name)
        discovery_url = ('https://accounts.google.com/.well-known/'
                         'openid-configuration')
        if not discovery:
            try:
                r = requests.get(discovery_url)
                discovery = r.json()
                discovery['provider'] = self.provider_name
                expiry_timestamp = mktime_tz(
                    parsedate_tz(r.headers['expires']))
                discovery['timestamp'] = expiry_timestamp
                oauth_db.insert(discovery)
            except Exception as e:
                print('WARNING: could not retrieve URLs for {}.'
                      .format(self.provider_name))
                print(e)
                discovery = {
                    'issuer': 'https://accounts.google.com',
                    'authorization_endpoint': 'https://accounts.google.com/'
                    'o/oauth2/v2/auth',
                    'token_endpoint': 'https://www.googleapis.com/oauth2/v4/'
                    'token'}
        elif (datetime.now(timezone.utc).timestamp() > discovery['timestamp']):
            try:
                last_expiry_date = datetime.fromtimestamp(
                    discovery['timestamp'], timezone.utc)
                headers = {
                    'If-Modified-Since': last_expiry_date
                    .strftime('%a, %d %b %Y %H:%M:%S %Z')}
                r = requests.get(discovery_url, headers=headers)
                if r.status_code != requests.codes.not_modified:
                    discovery.update(r.json())
                expiry_timestamp = mktime_tz(
                    parsedate_tz(r.headers['expires']))
                discovery['timestamp'] = expiry_timestamp
                oauth_db.update(discovery, doc_ids=[discovery.doc_id])
            except Exception as e:
                print('WARNING: could not update URLs for {}.'
                      .format(self.provider_name))
                print(e)

        self.service = OAuth2Service(
            name=self.provider_name,
            client_id=self.consumer_id,
            client_secret=self.consumer_secret,
            authorize_url=discovery['authorization_endpoint'],
            access_token_url=discovery['token_endpoint'],
            base_url=discovery['issuer'])

    def authorize(self):
        return redirect(self.service.get_authorize_url(
            scope='profile email',
            response_type='code',
            redirect_uri=self.get_callback_url()))

    def callback(self):
        if 'code' not in request.args:
            return (None, None, None)
        r = self.service.get_raw_access_token(
            method='POST',
            data={'code': request.args['code'],
                  'grant_type': 'authorization_code',
                  'redirect_uri': self.get_callback_url()})
        oauth_info = r.json()
        access_token = oauth_info['access_token']
        id_token = oauth_info['id_token']
        oauth_session = self.service.get_session(access_token)
        try:
            idinfo = client.verify_id_token(id_token, self.consumer_id)
            if idinfo['iss'] not in ['accounts.google.com',
                                     'https://accounts.google.com']:
                raise crypt.AppIdentityError("Wrong issuer.")
        except crypt.AppIdentityError as e:
            print(e)
            return (None, None, None)
        return (
            self.provider_name + '$' + idinfo['sub'],
            idinfo.get('name'),
            idinfo.get('email'))


class LinkedinSignIn(OAuthSignIn):
    def __init__(self):
        super(LinkedinSignIn, self).__init__('linkedin')
        self.formatted_name = 'LinkedIn'
        self.service = OAuth2Service(
            name=self.provider_name,
            client_id=self.consumer_id,
            client_secret=self.consumer_secret,
            authorize_url='https://www.linkedin.com/oauth/v2/authorization',
            access_token_url='https://www.linkedin.com/oauth/v2/accessToken',
            base_url='https://api.linkedin.com/v1/people/')

    def authorize(self):
        return redirect(self.service.get_authorize_url(
            scope='r_basicprofile r_emailaddress',
            response_type='code',
            redirect_uri=self.get_callback_url()))

    def callback(self):
        if 'code' not in request.args:
            return (None, None, None)
        r = self.service.get_raw_access_token(
            method='POST',
            data={'code': request.args['code'],
                  'grant_type': 'authorization_code',
                  'redirect_uri': self.get_callback_url()})
        oauth_info = r.json()
        access_token = oauth_info['access_token']
        oauth_session = self.service.get_session(access_token)
        idinfo = oauth_session.get(
            '~:(id,formatted-name,email-address)?format=json').json()
        return (
            self.provider_name + '$' + idinfo['id'],
            idinfo.get('formattedName'),
            idinfo.get('emailAddress'))


class TwitterSignIn(OAuthSignIn):
    def __init__(self):
        super(TwitterSignIn, self).__init__('twitter')
        self.formatted_name = 'Twitter'
        self.service = OAuth1Service(
            name=self.provider_name,
            consumer_key=self.consumer_id,
            consumer_secret=self.consumer_secret,
            request_token_url='https://api.twitter.com/oauth/request_token',
            authorize_url='https://api.twitter.com/oauth/authorize',
            access_token_url='https://api.twitter.com/oauth/access_token',
            base_url='https://api.twitter.com/1.1/')

    def authorize(self):
        request_token = self.service.get_request_token(
            params={'oauth_callback': self.get_callback_url()})
        session['request_token'] = request_token
        return redirect(self.service.get_authorize_url(request_token[0]))

    def callback(self):
        request_token = session.pop('request_token')
        if 'oauth_verifier' not in request.args:
            return (None, None, None)
        oauth_session = self.service.get_auth_session(
            request_token[0],
            request_token[1],
            data={'oauth_verifier': request.args['oauth_verifier']}
        )
        idinfo = oauth_session.get('account/verify_credentials.json').json()
        return (
            self.provider_name + '$' + str(idinfo.get('id')),
            idinfo.get('name'),
            # Need to write policy pages before retrieving email addresses
            None)


# Basic setup
# ===========
app = Flask(__name__, instance_relative_config=True)
# Data storage path defaults:
app.config['MAIN_DATABASE_PATH'] = os.path.join(
    app.instance_path, 'data', 'db.json')
app.config['USER_DATABASE_PATH'] = os.path.join(
    app.instance_path, 'data', 'users.json')
app.config['OAUTH_DATABASE_PATH'] = os.path.join(
    app.instance_path, 'oauth-urls.json')
app.config['OPENID_PATH'] = os.path.join(app.instance_path, 'open-id')
# Variable config options go here:
app.config.from_object('config.for.Production')
# Secret application keys go here:
app.config.from_pyfile('keys.cfg', silent=True)
# Any of these settings may be overridden in a .cfg file specified by the
# following environment variable:
app.config.from_envvar('MSC_SETTINGS', silent=True)
app.jinja_env.trim_blocks = True
app.jinja_env.lstrip_blocks = True

for path in [os.path.dirname(app.config['MAIN_DATABASE_PATH']),
             os.path.dirname(app.config['USER_DATABASE_PATH']),
             app.config['OPENID_PATH']]:
    if not os.path.isdir(path):
        print('INFO: creating empty data directory at {}'.format(path))
        os.makedirs(path)

lm = LoginManager(app)
lm.login_view = 'login'
lm.login_message = 'Please sign in to access this page.'
lm.login_message_category = "error"

db = TinyDB(
    app.config['MAIN_DATABASE_PATH'], storage=JSONStorageWithGit,
    sort_keys=True, indent=2, ensure_ascii=False)

user_db = TinyDB(
    app.config['USER_DATABASE_PATH'], storage=JSONStorageWithGit,
    sort_keys=True, indent=2, ensure_ascii=False)
oauth_db = TinyDB(app.config['OAUTH_DATABASE_PATH'])

thesaurus = rdflib.Graph()
thesaurus.parse('simple-unesco-thesaurus.ttl', format='turtle')
UNO = Namespace('http://vocabularies.unesco.org/ontology#')
thesaurus_link = ('<a href="http://vocabularies.unesco.org/browser/thesaurus/'
                  'en/">UNESCO Thesaurus</a>')

oid = OpenID(app, app.config['OPENID_PATH'])

auth = HTTPBasicAuth()

webhook = Webhook(app, secret=app.config['WEBHOOK_SECRET'])


class ApiUser(Document):
    '''For objects representing an application using the API. Source:
    https://blog.miguelgrinberg.com/post/restful-authentication-with-flask
    '''
    @property
    def is_active(self):
        if self.get('blocked'):
            return False
        return True

    @property
    def is_authenticated(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.doc_id)

    def __eq__(self, other):
        '''
        Checks the equality of two `UserMixin` objects using `get_id`.
        '''
        if isinstance(other, User):
            return self.get_id() == other.get_id()
        return NotImplemented

    def __ne__(self, other):
        '''
        Checks the inequality of two `UserMixin` objects using `get_id`.
        '''
        equal = self.__eq__(other)
        if equal is NotImplemented:
            return NotImplemented
        return not equal

    def hash_password(self, password):
        self['password_hash'] = pwd_context.encrypt(password)
        user_db.table('api_users').update(
            {'password_hash': self.get('password_hash')}, doc_ids=[self.doc_id])
        return True

    def verify_password(self, password):
        return pwd_context.verify_and_update(
            password, self.get('password_hash'))

    def generate_auth_token(self, expiration=600):
        s = Serializer(app.config['SECRET_KEY'], expires_in=expiration)
        return s.dumps({'id': self.doc_id})

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None  # valid token, but expired
        except BadSignature:
            return None  # invalid token
        api_users = user_db.table('api_users')
        user_record = api_users.get(doc_id=int(data['id']))
        if not user_record:
            return None
        user = ApiUser(value=user_record, doc_id=user_record.doc_id)
        return user


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

useful_fields = dict()
useful_fields['m'] = ['title', 'identifiers', 'description', 'keywords',
                      'locations']
useful_fields['g'] = ['name', 'identifiers']
useful_fields['t'] = ['title', 'identifiers', 'description', 'keywords',
                      'locations']
useful_fields['c'] = ['identifiers', 'locations', 'input_schemes',
                      'output_schemes']
useful_fields['e'] = ['identifiers', 'locations', 'endorsed_schemes']

computing_platforms = ['Windows', 'Mac OS X', 'Linux', 'BSD', 'cross-platform']

# Top 10 languages according to http://www.langpop.com/ in 2013.
# Though not really belonging here, 'XML' added for XSL tranformations.
programming_languages = [
    'C', 'Java', 'PHP', 'JavaScript', 'C++', 'Python', 'Shell', 'Ruby',
    'Objective-C', 'C#', 'XML']
programming_languages.sort()

id_scheme_list = ['DOI']

scheme_locations = [
    ('', ''), ('document', 'document'), ('website', 'website'),
    ('RDA-MIG', 'RDA MIG Schema'), ('DTD', 'XML/SGML DTD'),
    ('XSD', 'XML Schema'), ('RDFS', 'RDF Schema')]

organization_locations = [
    ('', ''), ('website', 'website'), ('email', 'email address')]
organization_types = [
    ('standards body', 'standards body'), ('archive', 'archive'),
    ('professional group', 'professional group'),
    ('coordination group', 'coordination group')]

tool_locations = [
    ('', ''), ('document', 'document'), ('website', 'website'),
    ('application', 'application'),
    ('service', 'service endpoint')]
tool_type_regexp = (
    r'(terminal \([^)]+\)|graphical \([^)]+\)|web service|web application|^$)')
tool_type_help = (
    'Must be one of "terminal (<platform>)", "graphical (<platform>)",'
    ' "web service", "web application".')
tool_type_list = ['web application', 'web service']
for platform in computing_platforms:
    tool_type_list.append('terminal ({})'.format(platform))
    tool_type_list.append('graphical ({})'.format(platform))

mapping_location_regexp = (
    r'(document|library \([^)]+\)|executable \([^)]+\)|^$)')
mapping_location_help = (html.escape(
    'Must be one of "document", "library (<language>)",'
    ' "executable (<platform>)".'))
mapping_location_list = ['document']
for language in programming_languages:
    mapping_location_list.append('library ({})'.format(language))
for platform in computing_platforms:
    mapping_location_list.append('executable ({})'.format(platform))

endorsement_locations = [('', ''), ('document', 'document')]


def get_subject_terms(complete=False):
    """Returns a list of subject terms. By default, only returns terms that
    would yield results in a search for metadata schemes. Pass `complete=True`
    to get a full list of all allowed subject terms.
    """
    keyword_uris = set()
    if complete:
        for generator in [
                thesaurus.subjects(RDF.type, UNO.Domain),
                thesaurus.subjects(RDF.type, UNO.MicroThesaurus),
                thesaurus.subjects(RDF.type, SKOS.Concept)]:
            for uri in generator:
                keyword_uris.add(uri)
    else:
        keyword_uris |= get_used_term_uris()
    subject_set = set()
    for uri in keyword_uris:
        subject_set.add(str(thesaurus.preferredLabel(uri, lang='en')[0][1]))
    subject_set.add('Multidisciplinary')
    subject_list = list(subject_set)
    subject_list.sort()
    return subject_list


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


def get_used_term_uris():
    """Returns a deduplicated list of URIs corresponding to the subject keywords
    in use in the database, plus the URIs of all their broader terms. Note that
    this does not look for version-specific keywords.
    """
    # Get a list of all the keywords used in the database
    Scheme = Query()
    classified_schemes = tables['m'].search(Scheme.keywords.exists())
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


def get_db_tree(series, document_list):
    """Takes a list of database documents and recursively builds a list of
    dictionaries providing each document's title, its corresponding URL in the
    Catalog, and (if applicable) a list of documents that are 'children' of
    the current document.

    Arguments:
        series (str): Record series
        document_list (list of Documents): List of records

    Returns:
        list: List of dictionaries, each of which with two or three items:
            'name' (the title of the scheme or tool), 'url' (the URL of the
            corresponding Catalog page), 'children' (list of child schemes,
            only present if there are any)
    """
    tree = list()
    for document in document_list:
        result = dict()
        if 'title' not in document:
            continue
        result['name'] = document['title']
        result['url'] = url_for('display', series=series, number=document.doc_id)
        if series == 'm':
            mscid = get_mscid(series, document.doc_id)
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


def abbrev_url(url):
    """Extracts last component of URL path. Useful for datatype URLs."""
    url_tuple = urllib.parse.urlparse(url)
    path = url_tuple.path
    if not path:
        return url
    path_fragments = path.split("/")
    if not path_fragments[-1] and len(path_fragments) > 1:
        return path_fragments[-2]
    return path_fragments[-1]


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

    def __init__(self, other_field_list, message=None, strip_whitespace=True):
        self.other_field_list = other_field_list
        self.message = message
        if strip_whitespace:
            self.string_check = lambda s: s.strip()
        else:
            self.string_check = lambda s: s

    def __call__(self, form, field):
        other_fields_empty = True
        for other_field_name in self.other_field_list:
            other_field = form._fields.get(other_field_name)
            if other_field is None:
                raise Exception(
                    'No field named "{}" in form'.format(other_field_name))
            if bool(other_field.data):
                self.field_flags = ('required', )
                if not field.raw_data or not field.raw_data[0]:
                    if self.message is None:
                        message = field.gettext('This field is required.')
                    else:
                        message = self.message
                    field.errors[:] = []
                    other_fields_empty = False
                    raise validators.StopValidation(message)
            elif (not field.raw_data) or (
                    isinstance(field.raw_data[0], string_types) and
                    not self.string_check(field.raw_data[0])):
                field.errors[:] = []
        if other_fields_empty:
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
    return mscid_prefix + series + str(number)


def get_relation(mscid, document):
    """Looks within an document for a relation to a given entity (represented
    by MSC ID) and returns tuple where the first member is a role list and the
    second is an Document.

    Arguments:
        mscid (str): MSC ID of entity beign checked for
        document (Document): TinyDB document being checked

    Returns:
        tuple: First member is a role list (str) and the second is an Document
    """
    role_list = ''
    # We take a fresh copy so the adjustments we make don't accumulate
    record = Document(value=document.copy(), doc_id=document.doc_id)
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
                                     .get(doc_id=entity_number))
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
        'abbrevURL': abbrev_url,
        'parseDateRange': parse_date_range}


@lm.user_loader
def load_user(id):
    document = user_db.get(doc_id=int(id))
    if document:
        return User(value=document, doc_id=document.doc_id)
    return None


# Front page
# ==========
@app.route('/')
def hello():
    return render_template('home.html')


# Terms of use
# ============
@app.route('/terms-of-use')
def terms_of_use():
    return render_template('terms-of-use.html')


# Display record
# ==============
@app.route('/msc/<string(length=1):series><int:number>')
@app.route('/msc/<string(length=1):series><int:number>/<field>')
def display(series, number, field=None, api=False):
    # Is this record in the database?
    if series not in table_names:
        abort(404)
    document = tables[series].get(doc_id=number)
    if not document:
        abort(404)

    # Form MSC ID
    mscid = get_mscid(series, number)

    # Return raw JSON if requested.
    if request_wants_json():
        api = True
    if api:
        if 'identifiers' not in document:
            document['identifiers'] = list()
        document['identifiers'].insert(0, {
            'id': mscid,
            'scheme': 'RDA-MSCWG'})
        if field:
            if field in document:
                return jsonify({field: document[field]})
            else:
                return jsonify()
        else:
            return jsonify(document)

    # We only provide dedicated views for metadata schemes and tools
    if series not in ['m', 't']:
        flash('The URL you requested is part of the Catalog API and has no'
              ' HTML equivalent. <a href="mailto:{}">Let us know</a> if you'
              ' would find an HTML view of {} useful.'
              .format(mscwg_email, table_names[series]), 'error')
        return redirect(url_for('hello'))

    # If the record has version information, interpret the associated dates.
    versions = None
    if 'versions' in document:
        versions = list()
        for v in document['versions']:
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
            print('WARNING: Record {}{} has missing version date.'
                  .format(mscid))
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
    if 'relatedEntities' in document:
        for entity in document['relatedEntities']:
            role = entity['role']
            if role not in relations_msc_form:
                print('WARNING: Record {} has related entity with unrecognized'
                      ' role "{}".'.format(mscid, role))
                continue
            relation_list = relations_msc_form[role]
            if relation_list not in relations:
                relations[relation_list] = list()
            entity_series, entity_number = parse_mscid(entity['id'])
            document_record = tables[entity_series].get(doc_id=entity_number)
            if document_record:
                relations[relation_list].append(document_record)
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
                role_list, document_record = get_relation(mscid, match)
                if role_list:
                    if role_list in [
                            'child schemes', 'mappings_to', 'mappings_from']:
                        hasRelatedSchemes = True
                    if role_list not in relations:
                        relations[role_list] = list()
                    relations[role_list].append(document_record)

    # We are ready to display the information.
    return render_template(
        'display-' + templates[series], record=document, versions=versions,
        relations=relations, hasRelatedSchemes=hasRelatedSchemes)


# Per-subject lists of standards
# ==============================
@app.route('/subject/<subject>')
def subject(subject):
    # If people start using geographical keywords, the following will need more
    # sophistication
    query_string = from_url_slug(subject)

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
    Scheme = Query()
    results = tables['m'].search(Scheme.keywords.any(term_list))
    no_of_hits = len(results)
    if no_of_hits:
        flash('Found {:N scheme/s}.'.format(Pluralizer(no_of_hits)))
        results.sort(key=lambda k: k['title'].lower())
    else:
        flash('No schemes have been associated with this subject area.'
              ' Would you like to see some <a href="{}">generic schemes</a>?'
              .format(url_for('subject', subject='Multidisciplinary')),
              'error')
    return render_template(
        'search-results.html', title=query_string, results=results)


# Per-datatype lists of standards
# ===============================
@app.route('/datatype/<path:dataType>')
def dataType(dataType):
    query_string = from_url_slug(dataType)
    Scheme = DataType = Query()
    results = tables['m'].search(Scheme.dataTypes.any(
        (DataType.url == query_string) |
        (DataType.label == query_string)))
    no_of_hits = len(results)
    if no_of_hits:
        flash('Found {:N scheme/s} used for this type of data.'
              .format(Pluralizer(no_of_hits)))
        results.sort(key=lambda k: k['title'].lower())
    else:
        flash('No schemes have been reported to be used for this type of'
              ' data.', 'error')
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
    document = tables['g'].get(doc_id=id)
    mscid = get_mscid('g', id)
    title = document['name']
    Scheme = Query()
    Relation = Query()
    results = tables['m'].search(Scheme.relatedEntities.any(
        (Relation.role == role) & (Relation.id == mscid)))
    no_of_hits = len(results)
    if no_of_hits:
        flash('Found {:N scheme/s} {} by this organization.'.format(
            Pluralizer(no_of_hits), verb))
    else:
        flash('No schemes found {} by this organization.'.format(verb),
              'error')
    return render_template('search-results.html', title=title, results=results)


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
        'contents.html', title='Index of metadata standards', tree=tree)


# List of tools
# =============
@app.route('/tool-index')
def tool_index():
    series = 't'
    matches = tables[series].search(Query().slug.exists())
    tree = get_db_tree(series, matches)
    return render_template(
        'contents.html', title='Index of metadata tools', tree=tree)


# Subject index
# =============
@app.route('/subject-index')
def subject_index():
    full_keyword_uris = get_used_term_uris()
    domains = thesaurus.subjects(RDF.type, UNO.Domain)
    tree = get_term_tree(domains, filter=full_keyword_uris)
    tree.insert(0, {
        'name': 'Multidisciplinary',
        'url': url_for('subject', subject='Multidisciplinary')})
    return render_template(
        'contents.html', title='Index of subjects', tree=tree)


# Forms: utilities
# ================
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


def msc_to_form(msc_data, padded=True):
    """Transforms data from MSC database into the data structure used by the
    web forms.

    Arguments:
        msc_data (dict): Record from the MSC database.
        padded (bool): Whether to add an empty member to the end of each list,
            so the user can complete it.

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
                        mapped_version['date'] = valid_tuple[0]
                        mapped_version['valid_to'] = valid_tuple[2]
                    else:
                        mapped_version[key] = value
                    if key == 'number':
                        mapped_version['number_old'] = value
                    if key == 'issued':
                        mapped_version['date'] = value
                if 'date' not in mapped_version and 'available' in version:
                    mapped_version['date'] = version['available']
                form_data[k].append(mapped_version)
            try:
                form_data[k].sort(key=lambda k: k['date'])
            except KeyError:
                form_data[k].sort(key=lambda k: k['number'])
        elif v:
            form_data[k] = v
    # Ensure there is a blank entry at the end of the following lists
    if padded:
        for l in ['keywords', 'types']:
            if l in form_data:
                form_data[l].append('')
        if 'dataTypes' in form_data:
            form_data['dataTypes'].append({'url': '', 'label': ''})
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


def form_to_msc(form_data, document):
    """Transforms data from web form into the MSC data model, supplemented by
    data that the form does not supply.

    Arguments:
        form_data (dict): Data from the form.
        document (dict or None): Existing record from the database that the
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
                        if document and 'versions' in document:
                            for release in document['versions']:
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
        elif k in ['keywords']:
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
    return msc_data


def fix_admin_data(record, series, number):
    """If the given record does not have a slug value, attempts to generate one.

    Arguments:
        record (dict): Dictionary using MSC data model.
        series (str): One of 'm', 'g', 't', 'c', 'e', referring to the type of
            record.
        number (int): EID of the currently held version of the record, or 0
            for a new record.

    Returns:
        dict: Dictionary using MSC data model.
    """
    # Restore any data not editable via the forms.
    table = tables[series]
    document = None
    if number:
        document = table.get(doc_id=number)
    if document:
        for key in ['slug']:  # room for expansion!
            if key in document:
                record[key] = document[key]
        # Exit if slug has been restored
        if 'slug' in record:
            return record
    # Otherwise attempt to generate slug from existing data
    slug = None
    if series == 'm' or series == 't':
        if 'title' in record:
            slug = to_file_slug(record['title'])
    elif series == 'g':
        if 'name' in record:
            slug = to_file_slug(record['name'])
    elif series == 'e':
        if 'citation' in record:
            slug = to_file_slug(record['citation'])
    elif series == 'c':
        if 'relatedEntities' in record:
            slug_from = ''
            slug_to = ''
            for entity in record['relatedEntities']:
                entity_series, entity_number = parse_mscid(entity['id'])
                if entity['role'] == 'input scheme':
                    document = tables[entity_series].get(doc_id=entity_number)
                    if 'slug' in document:
                        slug_from = document['slug']
                elif entity['role'] == 'output scheme':
                    document = tables[entity_series].get(doc_id=entity_number)
                    if 'slug' in document:
                        slug_to = document['slug']
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
    i = ''
    while table.search(Query().slug == (slug + str(i))):
        if i == '':
            i = 1
        else:
            i += 1
    else:
        record['slug'] = slug
    return record


def get_choices(series):
    """For a given series of records, returns a list of tuples, each
    consisting of an MSC ID and a title/name.

    Arguments:
        series (str): One of 'm', 'g', 't', 'c', 'e', referring to the type of
            record.

    Returns:
        list: Tuples containing an MSC ID and a human-friendly string.
    """
    choices = [('', '')]
    for document in tables[series].search(Query().slug.exists()):
        mscid = get_mscid(series, document.doc_id)
        for field in ['title', 'name', 'citation', 'slug']:
            if field in document:
                choices.append((mscid, document[field]))
                break
    choices.sort(key=lambda k: k[1].lower())
    return choices


# Search form
# ===========
class SchemeSearchForm(Form):
    title = StringField('Name of scheme')
    keywords = FieldList(
        StringField('Subject area', validators=[
            validators.Optional(),
            validators.AnyOf(
                get_subject_terms(complete=True),
                'Value must match an English preferred label in the {}.'
                .format(thesaurus_link))]),
        'Subject area', min_entries=1)
    keyword_id = StringField('URI of subject area term')
    identifier = StringField('Identifier')
    funder = StringField('Funder')
    funder_id = StringField('ID of funder')
    dataType = StringField('Data type')


@app.route('/query/schemes', methods=['POST'])
def api_query_scheme():
    return scheme_search(isGui=False)


@app.route('/search', methods=['GET', 'POST'])

@cross_origin()
def scheme_search(isGui=None):
    # Enable multiple keywords to be specified at once
    form_data = MultiDict(request.form)
    if 'keyword' in form_data and form_data['keyword']:
        keywords = form_data['keyword'].split('|')
        for index, kw in enumerate(keywords):
            form_data['keywords-{}'.format(index)] = kw
    form = SchemeSearchForm(form_data)
    # Process form
    if request.method == 'POST' and form.validate():
        document_list = list()
        mscid_list = list()
        Scheme = Version = Identifier = DataType = Funder = Relation = Query()
        if isGui is None:
            isGui = not request_wants_json()
        title = 'Search results'
        no_of_queries = 0

        if 'title' in form.data and form.data['title']:
            no_of_queries += 1
            title_query = wild_to_regex(form.data['title'])
            matches = tables['m'].search(Scheme.title.search(title_query))
            matches.extend(tables['m'].search(Scheme.versions.any(
                Version.title.search(title_query))))
            document_list, mscid_list = add_matches(
                'm', matches, document_list, mscid_list)
            if isGui:
                flash_result(matches, 'with title "{}"'
                             .format(form.data['title']))

        concept_ids = set()
        term_set = set()
        raw_term_set = set()
        if 'keywords' in form.data and form.data['keywords']:
            no_of_queries += 1
            for term in form.data['keywords']:
                raw_term_set.add(term)
                if term == 'Multidisciplinary':
                    # Use as is
                    term_set.add('Multidisciplinary')
                else:
                    # Translate term into concept ID
                    concept_id = get_term_uri(term)
                    if concept_id:
                        concept_ids.add(concept_id)
        if 'keyword_id' in form.data and form.data['keyword_id']:
            no_of_queries += 1
            kw_ids = form.data['keyword_id'].split('|')
            for kw_id in kw_ids:
                kw_uri = rdflib.term.URIRef(kw_id)
                if (kw_uri, None, None) in thesaurus:
                    concept_ids.add(kw_uri)
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
            matches.extend(tables['m'].search(Scheme.versions.any(
                Version.keywords.any(term_set))))
            document_list, mscid_list = add_matches(
                'm', matches, document_list, mscid_list)
            if isGui:
                flash_result(matches, 'related to {}'
                             .format(" and ".join(raw_term_set)))

        if 'identifier' in form.data and form.data['identifier']:
            no_of_queries += 1
            matches = list()
            series, number = parse_mscid(form.data['identifier'])
            if (series == 'm') and number:
                matches.append(tables[series].get(doc_id=number))
            else:
                matches.extend(tables['m'].search(Scheme.identifiers.any(
                    Identifier.id == form.data['identifier'])))
                matches.extend(tables['m'].search(Scheme.versions.any(
                    Version.identifiers.any(
                        Identifier.id == form.data['identifier']))))
            document_list, mscid_list = add_matches(
                'm', matches, document_list, mscid_list)
            if isGui:
                flash_result(matches, 'with identifier "{}"'
                             .format(form.data['identifier']))

        matching_funders = list()
        if 'funder' in form.data and form.data['funder']:
            no_of_queries += 1
            # Interpret search
            funder_query = wild_to_regex(form.data['funder'])
            funder_search = tables['g'].search(Funder.name.search(
                funder_query))
            matches = list()
            for funder in funder_search:
                funder_mscid = get_mscid('g', funder.doc_id)
                matches.append(funder_mscid)
            if matches:
                matching_funders.extend(matches)
            elif isGui:
                flash('No funders found called "{}" .'.format(
                    form.data['funder']), 'error')
        if 'funder_id' in form.data and form.data['funder_id']:
            series, number = parse_mscid(form.data['funder_id'])
            matches = list()
            if (series == 'g') and number:
                matches.append(tables[series].get(doc_id=number))
            else:
                matches.extend(tables['g'].search(Funder.identifiers.any(
                    Identifier.id == form.data['funder_id'])))
            if matches:
                matching_funders.extend(matches)
            elif isGui:
                flash('No funders found with identifier "{}" .'.format(
                    form.data['funder_id']), 'error')
        if matching_funders:
            matches = list()
            for funder_mscid in matching_funders:
                matches.extend(tables['m'].search(
                    Scheme.relatedEntities.any(
                        (Relation.role == 'funder') &
                        (Relation.id == funder_mscid))))
                matches.extend(tables['m'].search(
                    Scheme.versions.any(Version.relatedEntities.any(
                        (Relation.role == 'funder') &
                        (Relation.id == funder_mscid)))))
            document_list, mscid_list = add_matches(
                'm', matches, document_list, mscid_list)
            if isGui:
                flash_result(
                    matches,
                    'with funder "{}"'
                    .format(form.data['funder'] or form.data['funder_id']))

        if 'dataType' in form.data and form.data['dataType']:
            no_of_queries += 1
            matches = tables['m'].search(
                Scheme.dataTypes.any(
                    (DataType.url == form.data['dataType']) |
                    (DataType.label == form.data['dataType'])))
            matches.extend(tables['m'].search(Scheme.versions.any(
                Version.dataTypes.any(
                    (DataType.url == form.data['dataType']) |
                    (DataType.label == form.data['dataType'])))))
            document_list, mscid_list = add_matches(
                'm', matches, document_list, mscid_list)
            if isGui:
                flash_result(matches, 'associated with {}'
                             .format(form.data['dataType']))

        # Show results
        if isGui:
            no_of_hits = len(document_list)
            if no_of_queries > 1:
                flash('Found {:N scheme/s} in total. '.format(
                    Pluralizer(no_of_hits)))
            if no_of_hits == 1:
                # Go direct to that page
                result = document_list.pop()
                return redirect(
                    url_for('display', series='m', number=result.doc_id))
            # Otherwise return as a list
            document_list.sort(key=lambda k: k['title'].lower())
            # Show results list
            return render_template(
                'search-results.html', title=title, results=document_list)
        else:
            n = len(mscid_prefix) + 1
            mscid_list.sort(key=lambda k: k[:n] + k[n:].zfill(5))
            return jsonify({'ids': mscid_list})

    else:
        # Title, identifier, funder, dataType help
        all_schemes = tables['m'].all()
        title_set = set()
        id_set = set()
        type_set = set()
        funder_set = set()
        for scheme in all_schemes:
            id_set.add(get_mscid('m', scheme.doc_id))
            title_set, id_set, type_set, funder_set = extract_hints(
                scheme, title_set, id_set, type_set, funder_set)
        title_list = list(title_set)
        title_list.sort(key=lambda k: k.lower())
        id_list = list(id_set)
        n = len(mscid_prefix) + 1
        id_list.sort(key=lambda k: k[:n] + k[n:].zfill(5))
        funder_list = list(funder_set)
        funder_list.sort(key=lambda k: k.lower())
        type_list = list(type_set)
        type_list.sort(key=lambda k: k.lower())
        # Subject help
        subject_list = get_subject_terms()
        return render_template(
            'search-form.html', form=form, titles=title_list,
            subjects=subject_list, ids=id_list, funders=funder_list,
            dataTypes=type_list)


class GroupSearchForm(Form):
    name = StringField('Name of organization')
    identifier = StringField('Identifier')
    type = SelectMultipleField(
        'Type of organization', choices=organization_types)


@app.route('/query/organizations', methods=['POST'])
def api_query_group():
    form = GroupSearchForm(request.form)
    # Process form
    if request.method == 'POST' and form.validate():
        return api_query('g', form)


class ToolSearchForm(Form):
    title = StringField('Name of tool')
    identifier = StringField('Identifier')
    type = FieldList(
        StringField('Type', validators=[
            validators.Regexp(tool_type_regexp, message=tool_type_help)]),
        'Type of tool', min_entries=1)
    supported_scheme = StringField('Supported metadata scheme')


@app.route('/query/tools', methods=['POST'])
def api_query_tool():
    form = ToolSearchForm(request.form)
    # Process form
    if request.method == 'POST' and form.validate():
        return api_query('t', form)


class MappingSearchForm(Form):
    identifier = StringField('Identifier')
    input_scheme = StringField('Input metadata scheme')
    output_scheme = StringField('Output metadata scheme')


@app.route('/query/mappings', methods=['POST'])
def api_query_mapping():
    form = MappingSearchForm(request.form)
    # Process form
    if request.method == 'POST' and form.validate():
        return api_query('c', form)


class EndorsementSearchForm(Form):
    identifier = StringField('Identifier')
    endorsed_scheme = StringField('Endorsed scheme')


@app.route('/query/endorsements', methods=['POST'])
def api_query_endorsement():
    form = EndorsementSearchForm(request.form)
    # Process form
    if request.method == 'POST' and form.validate():
        return api_query('e', form)


def api_query(series, form):
    document_list = list()
    mscid_list = list()
    Record = Version = Identifier = Relation = Query()
    title = 'Search results'
    no_of_queries = 0

    if 'name' in form.data and form.data['name']:
        no_of_queries += 1
        name_query = wild_to_regex(form.data['name'])
        matches = tables[series].search(Record.name.search(name_query))
        matches.extend(tables[series].search(Record.versions.any(
            Version.name.search(name_query))))
        document_list, mscid_list = add_matches(
            series, matches, document_list, mscid_list)

    if 'title' in form.data and form.data['title']:
        no_of_queries += 1
        title_query = wild_to_regex(form.data['title'])
        matches = tables[series].search(Record.title.search(title_query))
        matches.extend(tables[series].search(Record.versions.any(
            Version.title.search(title_query))))
        document_list, mscid_list = add_matches(
            series, matches, document_list, mscid_list)

    if 'identifier' in form.data and form.data['identifier']:
        no_of_queries += 1
        matches = list()
        id_series, id_number = parse_mscid(form.data['identifier'])
        if (id_series == series) and id_number:
            matches.append(tables[series].get(doc_id=id_number))
        else:
            matches.extend(tables[series].search(Record.identifiers.any(
                Identifier.id == form.data['identifier'])))
            matches.extend(tables[series].search(Record.versions.any(
                Version.identifiers.any(
                    Identifier.id == form.data['identifier']))))
        document_list, mscid_list = add_matches(
            series, matches, document_list, mscid_list)

    if 'type' in form.data and form.data['type']:
        no_of_queries += 1
        matches = tables[series].search(
            Record.types.any([form.data['type']]))
        matches.extend(tables[series].search(Record.versions.any(
            Version.types.any([form.data['type']]))))
        document_list, mscid_list = add_matches(
            series, matches, document_list, mscid_list)

    if 'input_scheme' in form.data and form.data['input_scheme']:
        no_of_queries += 1
        if 'output_scheme' in form.data and form.data['output_scheme']:
            # Also match a version-level identifier
            matches = tables[series].search(
                Record.relatedEntities.any(
                    (Relation.role == 'input scheme') &
                    (Relation.id.search(
                        '{}(#.*)?'.format(form.data['input_scheme'])))) &
                Record.relatedEntities.any(
                    (Relation.role == 'output scheme') &
                    (Relation.id.search(
                        '{}(#.*)?'.format(form.data['output_scheme'])))))
            matches.extend(tables[series].search(Record.versions.any(
                Version.relatedEntities.any(
                    (Relation.role == 'input scheme') &
                    (Relation.id.search(
                        '{}(#.*)?'.format(form.data['input_scheme'])))) &
                Version.relatedEntities.any(
                    (Relation.role == 'output scheme') &
                    (Relation.id.search(
                        '{}(#.*)?'.format(form.data['output_scheme'])))))))
            document_list, mscid_list = add_matches(
                series, matches, document_list, mscid_list)
        else:
            # Also match a version-level identifier
            matches = tables[series].search(
                Record.relatedEntities.any(
                    (Relation.role == 'input scheme') &
                    (Relation.id.search(
                        '{}(#.*)?'.format(form.data['input_scheme'])))))
            matches.extend(tables[series].search(Record.versions.any(
                Version.relatedEntities.any(
                    (Relation.role == 'input scheme') &
                    (Relation.id.search(
                        '{}(#.*)?'.format(form.data['input_scheme'])))))))
            document_list, mscid_list = add_matches(
                series, matches, document_list, mscid_list)
    elif 'output_scheme' in form.data and form.data['output_scheme']:
        no_of_queries += 1
        # Also match a version-level identifier
        matches = tables[series].search(
            Record.relatedEntities.any(
                (Relation.role == 'output scheme') &
                (Relation.id.search(
                    '{}(#.*)?'.format(form.data['output_scheme'])))))
        matches.extend(tables[series].search(Record.versions.any(
            Version.relatedEntities.any(
                (Relation.role == 'output scheme') &
                (Relation.id.search(
                    '{}(#.*)?'.format(form.data['output_scheme'])))))))
        document_list, mscid_list = add_matches(
            series, matches, document_list, mscid_list)

    for role in ['supported_scheme', 'endorsed_scheme']:
        if role in form.data and form.data[role]:
            no_of_queries += 1
            # Also match a version-level identifier
            matches = tables[series].search(
                Record.relatedEntities.any(
                    (Relation.role == role.replace('_', ' ')) &
                    (Relation.id.search(
                        '{}(#.*)?'.format(form.data[role])))))
            matches.extend(tables[series].search(Record.versions.any(
                Version.relatedEntities.any(
                    (Relation.role == role.replace('_', ' ')) &
                    (Relation.id.search(
                        '{}(#.*)?'.format(form.data[role])))))))
            document_list, mscid_list = add_matches(
                series, matches, document_list, mscid_list)

    n = len(mscid_prefix) + 1
    mscid_list.sort(key=lambda k: k[:n] + k[n:].zfill(5))
    return jsonify({'ids': mscid_list})


def add_matches(series, matches, document_list, mscid_list):
    """Scans list of database documents and adds them to a given list of
    documents and a given list of EIDs, but only if they are not already
    there.

    Arguments:
        matches (list of Documents): New list of records
        document_list (list of Documents): Existing list of records
        doc_id_list (list of str): Existing list of MSC IDs

    Returns:
        tuple: list of records and list of EIDs
    """
    for document in matches:
        mscid = get_mscid(series, document.doc_id)
        if mscid not in mscid_list:
            document_list.append(document)
            mscid_list.append(mscid)
    return (document_list, mscid_list)


def extract_hints(scheme, title_set, id_set, type_set, funder_set):
    """Extracts sets of identifiers, data types and funders from a dictionary
    of metadata scheme properties. Note that the set of identifiers will not
    contain the MSC ID for the record.

    Arguments:
        scheme (dict): The dictionary of properties (for a metadata scheme or
            version thereof) in which to look.
        title_set (set): Set of titles.
        id_set (set): Set of identifiers.
        type_set (set): Set of data types.
        funder_set (set): Set of funder names.

    Returns:
        tuple: The four sets passed to the function (in the same order) with
            any new values added.
    """
    if 'title' in scheme:
        title_set.add(scheme['title'])
    if 'identifiers' in scheme:
        for identifier in scheme['identifiers']:
            id_set.add(identifier['id'])
    if 'dataTypes' in scheme:
        for type in scheme['dataTypes']:
            type_url = type.get('url')
            if type_url:
                type_set.add(type_url)
            type_label = type.get('label')
            if type_label:
                type_set.add(type_label)
    if 'relatedEntities' in scheme:
        for entity in scheme['relatedEntities']:
            if entity['role'] == 'funder':
                org_series, org_number = parse_mscid(entity['id'])
                funder = tables[org_series].get(doc_id=org_number)
                if funder:
                    funder_set.add(funder['name'])
                else:
                    print('Could not look up organization with doc_id {}.'
                          .format(org_number))
    if 'versions' in scheme:
        for version in scheme['versions']:
            title_set, id_set, type_set, funder_set = extract_hints(
                version, title_set, id_set, type_set, funder_set)
    return (title_set, id_set, type_set, funder_set)


def flash_result(matches, type):
    """Flashes user with informative message about a search result, based on
    thing they are supposed to have in common.

    Arguments:
        matches (list of Documents): List of records
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
class LoginForm(FlaskForm):
    openid = StringField('OpenID URL', validators=[validators.URL])


@app.route('/login', methods=['GET', 'POST'])
@oid.loginhandler
def login():
    '''This login view can handle both OpenID v2 and OpenID Connect
    authentication. The POST method begins the OpenID v2 process. The
    OpenID Connect links route to oauth_authorize() instead.
    '''
    if current_user.is_authenticated:
        return redirect(oid.get_next_url())
    form = LoginForm(request.form)
    if request.method == 'POST' and form.validate():
        openid = form.openid.data
        if openid:
            return oid.try_login(
                openid, ask_for=['email', 'nickname'],
                ask_for_optional=['fullname'])
    error = oid.fetch_error()
    if error:
        flash(error, 'error')
    providers = list()
    if 'OAUTH_CREDENTIALS' in app.config:
        for provider_class in OAuthSignIn.__subclasses__():
            provider = provider_class()
            providers.append({
                'name': provider.formatted_name,
                'slug': provider.provider_name})
        providers.sort(key=lambda k: k['slug'])
    return render_template(
        'login.html', form=form, providers=providers, next=oid.get_next_url())


@oid.after_login
def create_or_login(resp):
    '''This function handles the response from an OpenID v2 provider.
    '''
    session['openid'] = resp.identity_url
    User = Query()
    profile = user_db.get(User.userid == resp.identity_url)
    if profile:
        flash('Successfully signed in.')
        user = load_user(profile.doc_id)
        login_user(user)
        return redirect(oid.get_next_url())
    return redirect(url_for(
        'create_profile', next=oid.get_next_url(),
        name=resp.fullname or resp.nickname, email=resp.email))


@app.route('/authorize/<provider>')
def oauth_authorize(provider):
    '''This function calls out to the OpenID Connect provider.
    '''
    if not current_user.is_anonymous:
        return redirect(url_for('hello'))
    oauth = OAuthSignIn.get_provider(provider)
    return oauth.authorize()


@app.route('/callback/<provider>')
def oauth_callback(provider):
    '''The OpenID Connect provider sends information back to this URL,
    where we use it to extract a unique ID, user name and email address.
    '''
    if not current_user.is_anonymous:
        return redirect(url_for('hello'))
    oauth = OAuthSignIn.get_provider(provider)
    openid, username, email = oauth.callback()
    session['openid'] = openid
    if openid is None:
        flash('Authentication failed.')
        return redirect(url_for('hello'))
    User = Query()
    profile = user_db.get(User.userid == openid)
    if profile:
        flash('Successfully signed in.')
        user = load_user(profile.doc_id)
        login_user(user)
        return redirect(url_for('hello'))
    return redirect(url_for(
        'create_profile', next=url_for('hello'),
        name=username, email=email))


class ProfileForm(FlaskForm):
    name = StringField('Name', validators=[validators.InputRequired(
        message='You must provide a user name.')])
    email = StringField('Email', validators=[validators.InputRequired(
        message='You must enter an email address.'), validators.Email(
        message='You must enter a valid email address.')])


@app.route('/create-profile', methods=['GET', 'POST'])
def create_profile():
    '''If the user authenticated successfully by either means, but does
    not exist in the user database, this view creates and saves their profile.
    '''
    if current_user.is_authenticated or 'openid' not in session:
        if 'openid' not in session:
            flash('OpenID sign-in failed, sorry.', 'error')
        return redirect(url_for('hello'))
    form = ProfileForm(request.values)
    if request.method == 'POST' and form.validate():
        name = request.form['name']
        email = request.form['email']
        data = {
            'name': form.name.data,
            'email': form.email.data,
            'userid': session['openid']}
        user_doc_id = user_db.insert(data)
        flash('Profile successfully created.')
        user = User(value=data, doc_id=user_doc_id)
        login_user(user)
        return redirect(oid.get_next_url() or url_for('hello'))
    return render_template(
        'create-profile.html', form=form,
        next=oid.get_next_url() or url_for('hello'))


@app.route('/edit-profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    '''Allows users to change their displayed username and email address.
    '''
    openid_formatted = 'unknown profile'
    openid_tuple = current_user['userid'].partition('$')
    if openid_tuple[2]:
        # OpenID Connect profile
        openid_format = '{} profile for '
        for provider_class in OAuthSignIn.__subclasses__():
            provider = provider_class()
            if openid_tuple[0] == provider.provider_name:
                openid_formatted = (openid_format
                                    .format(provider.formatted_name))
                break
        else:
            openid_formatted = (openid_format
                                .format(openid_tuple[0]))
        openid_formatted += current_user['name']
    else:
        # OpenID v2 profile
        openid_formatted = current_user['userid']
    form = ProfileForm(request.values, data=current_user)
    if request.method == 'POST' and form.validate():
        name = request.form['name']
        email = request.form['email']
        data = {
            'name': form.name.data,
            'email': form.email.data,
            'userid': current_user['userid']}
        if user_db.update(data, doc_ids=[current_user.doc_id]):
            flash('Profile successfully updated.')
        else:
            flash('Profile could not be updated, sorry.')
        return redirect(url_for('hello'))
    return render_template(
        'edit-profile.html', form=form, openid_formatted=openid_formatted)


@app.route('/remove-profile')
@login_required
def remove_profile():
    '''Allows users to remove their profile from the system.
    '''
    if user_db.remove(doc_ids=[current_user.doc_id]):
        flash('Your profile was successfully deleted.')
        logout_user()
        session.pop('openid', None)
        flash('You were signed out.')
    else:
        flash('Your profile could not be deleted.')
    return redirect(url_for('hello'))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('openid', None)
    flash('You were signed out.')
    return redirect(url_for('hello'))


# API authentication
# ==================
#
# Source: https://blog.miguelgrinberg.com/post/restful-authentication-with-flask
@app.route('/api/reset-password', methods=['POST'])
@auth.login_required
def reset_api_password():
    new_password = request.json.get('new_password')
    if g.user.hash_password(new_password):
        return jsonify(
            {'username': g.user.get('name'), 'password_reset': 'true'})
    else:
        abort(500)


@app.route('/api/token')
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token()
    return jsonify({'token': token.decode('ascii')})


@auth.verify_password
def verify_password(userid_or_token, password):
    # first try to authenticate by token
    user = ApiUser.verify_auth_token(userid_or_token)
    if not user:
        # try to authenticate with username/password
        api_users = user_db.table('api_users')
        User = Query()
        user_record = api_users.get(User.userid == userid_or_token)
        if not user_record:
            return False
        user = ApiUser(value=user_record, doc_id=user_record.doc_id)
        if not user.verify_password(password) or not user.is_active:
            return False
        g.user = user
        return True


# Forms: editing
# ==============
#
# General editing form components
# -------------------------------
class NativeDateField(StringField):
    widget = widgets.Input(input_type='date')
    validators = [validators.Optional(), W3CDate]


class DataTypeForm(Form):
    label = StringField('Data type', default='')
    url = StringField('URL of definition', validators=[
        validators.Optional(), EmailOrURL])


class LocationForm(Form):
    url = StringField('URL', validators=[RequiredIf(['type']), EmailOrURL])
    type = SelectField('Type', validators=[RequiredIf(['url'])], default='')


class FreeLocationForm(Form):
    url = StringField('URL', validators=[RequiredIf(['type']), EmailOrURL])
    type = StringField('Type', validators=[RequiredIf(['url'])], default='')


class SampleForm(Form):
    title = StringField('Title', validators=[RequiredIf(['url'])])
    url = StringField('URL', validators=[RequiredIf(['title']), EmailOrURL])


class IdentifierForm(Form):
    id = StringField('ID')
    scheme = StringField('ID scheme')


class VersionForm(Form):
    number = StringField('Version number', validators=[
        RequiredIf(['issued', 'available', 'valid_from']), validators.Length(max=20)])
    number_old = HiddenField(validators=[validators.Length(max=20)])
    issued = NativeDateField('Date published')
    available = NativeDateField('Date released as draft/proposal')
    valid_from = NativeDateField('Date considered current')
    valid_to = NativeDateField('until')


class SchemeVersionForm(Form):
    scheme_choices = get_choices('m')

    id = SelectField('Metadata scheme', choices=scheme_choices)
    version = StringField('Version')


class CreatorForm(Form):
    fullName = StringField('Full name')
    givenName = StringField('Given name(s)')
    familyName = StringField('Family name')


# Editing metadata schemes
# ------------------------
class SchemeForm(FlaskForm):
    title = StringField('Name of metadata scheme')
    description = TextAreaField('Description')
    keywords = FieldList(
        StringField('Subject area', validators=[
            validators.Optional(),
            validators.AnyOf(
                get_subject_terms(complete=True),
                'Value must match an English preferred label in the {}.'
                .format(thesaurus_link))]),
        'Subject areas', min_entries=1)
    dataTypes = FieldList(
        FormField(DataTypeForm), 'Data types', min_entries=1)
    parent_schemes = SelectMultipleField('Parent metadata scheme(s)')
    maintainers = SelectMultipleField(
        'Organizations that maintain this scheme')
    funders = SelectMultipleField('Organizations that funded this scheme')
    users = SelectMultipleField('Organizations that use this scheme')
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


# Editing organizations
# ---------------------
class OrganizationForm(FlaskForm):
    name = StringField('Name of organization')
    description = TextAreaField('Description')
    types = SelectMultipleField(
        'Type of organization', choices=organization_types)
    locations = FieldList(
        FormField(LocationForm), 'Relevant links', min_entries=1)
    identifiers = FieldList(
        FormField(IdentifierForm), 'Identifiers for this organization',
        min_entries=1)


# Editing tools
# -------------
class ToolForm(FlaskForm):
    title = StringField('Name of tool')
    description = TextAreaField('Description')
    supported_schemes = SelectMultipleField(
        'Metadata scheme(s) supported by this tool')
    types = FieldList(
        StringField('Type', validators=[
            validators.Regexp(tool_type_regexp, message=tool_type_help)]),
        'Type of tool', min_entries=1)
    creators = FieldList(
        FormField(CreatorForm), 'People responsible for this tool',
        min_entries=1)
    maintainers = SelectMultipleField('Organizations that maintain this tool')
    funders = SelectMultipleField('Organizations that funded this tool')
    locations = FieldList(
        FormField(LocationForm), 'Links to this tool', min_entries=1)
    identifiers = FieldList(
        FormField(IdentifierForm), 'Identifiers for this tool', min_entries=1)
    versions = FieldList(
        FormField(VersionForm), 'Version history', min_entries=1)


# Editing mappings
# ----------------
class MappingForm(FlaskForm):
    description = TextAreaField('Description')
    input_schemes = SelectMultipleField('Input metadata scheme(s)')
    output_schemes = SelectMultipleField('Output metadata scheme(s)')
    creators = FieldList(
        FormField(CreatorForm), 'People responsible for this mapping',
        min_entries=1)
    maintainers = SelectMultipleField(
        'Organizations that maintain this mapping',
        choices=get_choices('g'))
    funders = SelectMultipleField('Organizations that funded this mapping')
    locations = FieldList(
        FormField(FreeLocationForm), 'Links to this mapping', min_entries=1)
    identifiers = FieldList(
        FormField(IdentifierForm), 'Identifiers for this mapping',
        min_entries=1)
    versions = FieldList(
        FormField(VersionForm), 'Version history', min_entries=1)


# Editing endorsements
# --------------------
class EndorsementForm(FlaskForm):
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
    originators = SelectMultipleField('Endorsing organizations')


Forms = {
    'm': SchemeForm,
    'g': OrganizationForm,
    't': ToolForm,
    'c': MappingForm,
    'e': EndorsementForm}


# Ensuring consistency of data type/URL pairs
# -------------------------------------------
def propagate_data_types(msc_data, table, t):
    """Takes a record, a table, and a transaction. For each data type URL/label
    pair, ensures all other occurrences of the URL in the table are accompanied
    by the same label. Returns the number of updated records."""
    changes_made = 0

    if 'dataTypes' not in msc_data:
        return changes_made

    Scheme = Version = DataType = Query()
    for dataType in msc_data['dataTypes']:
        if not dataType.get('url'):
            continue
        if not dataType.get('label'):
            continue
        matches = table.search(
            Scheme.dataTypes.any(
                (DataType.url == dataType['url'])))
        for match in matches:
            needs_updating = False
            old_dataTypes = match['dataTypes']
            new_dataTypes = list()
            for type in old_dataTypes:
                if (type.get('url') == dataType['url'] and
                        type.get('label') != dataType['label']):
                    needs_updating = True
                    new_dataTypes.append(dataType)
                else:
                    new_dataTypes.append(type)
            if needs_updating:
                t.update({'dataTypes': new_dataTypes}, eids=[match.doc_id])
                changes_made += 1
        matches = table.search(
            Scheme.versions.any(
                Version.dataTypes.any(
                    (DataType.url == dataType['url']))))
        for match in matches:
            needs_updating = False
            new_versions = list()
            for version in match['versions']:
                if 'dataTypes' not in version:
                    new_versions.append(version)
                    continue
                old_dataTypes = version['dataTypes']
                new_dataTypes = list()
                for type in old_dataTypes:
                    if (type.get('url') == dataType['url'] and
                            type.get('label') != dataType['label']):
                        needs_updating = True
                        new_dataTypes.append(dataType)
                    else:
                        new_dataTypes.append(type)
                new_version = version
                new_version['dataTypes'] = new_dataTypes
                new_versions.append(new_version)
            if needs_updating:
                t.update({'versions': new_versions}, eids=[match.doc_id])
                changes_made += 1
    return changes_made


# Generic editing form view
# -------------------------
@app.route('/edit/<string(length=1):series><int:number>',
           methods=['GET', 'POST'])
@login_required
def edit_record(series, number):
    document = tables[series].get(doc_id=number)
    version = request.values.get('version')
    if version and request.referrer == request.base_url:
        # This is the version screen, opened from the main screen
        flash('Only provide information here that is different from the'
              ' information in the main (non-version-specific) record.')

    # Instantiate form
    if document:
        # Translate from internal data model to form data
        if version:
            for release in document['versions']:
                if 'number' in release and\
                        str(release['number']) == str(version):
                    form = Forms[series](
                        request.form, data=msc_to_form(release))
                    break
            else:
                form = Forms[series](request.form)
            del form['versions']
        else:
            form = Forms[series](request.form, data=msc_to_form(document))
    else:
        if number != 0:
            return redirect(url_for('edit_record', series=series, number=0))
        form = Forms[series](request.form)

    # Form-specific value lists
    params = dict()
    scheme_choices = get_choices('m')
    organization_choices = get_choices('g')
    if series == 'm':
        # Subject keyword help
        subject_list = get_subject_terms(complete=True)
        params['subjects'] = subject_list
        # Data type help
        type_url_set = set()
        type_label_set = set()
        for scheme in tables['m'].all():
            if 'dataTypes' in scheme:
                for type in scheme['dataTypes']:
                    type_url = type.get('url')
                    if type_url:
                        type_url_set.add(type_url)
                    type_label = type.get('label')
                    if type_label:
                        type_label_set.add(type_label)
        type_url_list = list(type_url_set)
        type_label_list = list(type_label_set)
        type_url_list.sort(key=lambda k: k.lower())
        type_label_list.sort(key=lambda k: k.lower())
        params['dataTypeURLs'] = type_url_list
        params['dataTypeLabels'] = type_label_list
        # Validation for parent schemes
        form.parent_schemes.choices = scheme_choices
        # Validation for organizations
        form.maintainers.choices = organization_choices
        form.funders.choices = organization_choices
        form.users.choices = organization_choices
        # Validation for URL types
        for f in form.locations:
            f['type'].choices = scheme_locations
    elif series == 'g':
        # Validation for URL types
        for f in form.locations:
            f['type'].choices = organization_locations
    elif series == 't':
        # Tool type help
        params['toolTypes'] = tool_type_list
        # Validation for parent schemes
        form.supported_schemes.choices = scheme_choices
        # Validation for organizations
        form.maintainers.choices = organization_choices
        form.funders.choices = organization_choices
        # Validation for URL types
        for f in form.locations:
            f['type'].choices = tool_locations
    elif series == 'c':
        # Validation for parent schemes
        form.input_schemes.choices = scheme_choices
        form.output_schemes.choices = scheme_choices
        # Validation for organizations
        form.maintainers.choices = organization_choices
        form.funders.choices = organization_choices
        # Validation for URL types
        for f in form.locations:
            f['type'].validators.append(
                validators.Regexp(
                    regex=mapping_location_regexp, message=mapping_location_help))
        params['locationTypes'] = mapping_location_list
    elif series == 'e':
        # Validation for organizations
        form.originators.choices = organization_choices
        # Validation for URL types; note that as there is a choice of one,
        # we apply it automatically, not via the form.
        for f in form.locations:
            f['type'].choices = endorsement_locations
            f.url.validators = [validators.Optional()]
            f['type'].validators = [validators.Optional()]

    # Processing the request
    if request.method == 'POST' and form.validate():
        form_data = form.data
        if series == 'e':
            # Here is where we automatically insert the URL type
            filtered_locations = list()
            for f in form.locations:
                if f.url.data:
                    location = {'url': f.url.data, 'type': 'document'}
                    filtered_locations.append(location)
            form_data['locations'] = filtered_locations
        # Translate form data into internal data model
        msc_data = form_to_msc(form_data, document)
        if version:
            # Editing the version-specific overrides
            if document and 'versions' in document:
                version_list = document['versions']
                for index, item in enumerate(version_list):
                    if str(item['number']) == str(version):
                        version_dict = {
                            k: v for k, v in item.items()
                            if k in ['number', 'available', 'issued', 'valid']}
                        version_dict.update(msc_data)
                        version_list[index] = version_dict
                        Record = Query()
                        Version = Query()
                        tables[series].update(
                            {'versions': version_list},
                            Record.versions.any(Version.number == version),
                            doc_ids=[number])
                        records_updated = 0
                        if 'dataTypes' in msc_data:
                            with transaction(tables[series]) as t:
                                records_updated = propagate_data_types(
                                    msc_data, tables[series], t)
                        flash('Successfully updated record for version {}.'
                              .format(version), 'success')
                        if records_updated:
                            flash('Also updated the data types of {:/1 other'
                                  ' record/N other records}.'
                                  .format(Pluralizer(records_updated)),
                                  'success')
                        flash('If this page opened in a new window or tab, feel'
                              ' free to close it now.')
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
                'edit_record', series=series, number=number), version))
        elif document:
            # Editing an existing record
            msc_data = fix_admin_data(msc_data, series, number)
            with transaction(tables[series]) as t:
                for key in (k for k in document if k not in msc_data):
                    t.update_callable(delete(key), eids=[number])
                t.update(msc_data, eids=[number])
            # Ensure consistency of dataType url/label pairs
            records_updated = 0
            if 'dataTypes' in msc_data:
                with transaction(tables[series]) as t:
                    records_updated = propagate_data_types(
                        msc_data, tables[series], t)
            flash('Successfully updated record.', 'success')
            if records_updated:
                flash('Also updated the data types of {:/1 other record/N other'
                      ' records}.'.format(Pluralizer(records_updated)),
                      'success')
        else:
            # Adding a new record
            msc_data = fix_admin_data(msc_data, series, number)
            number = tables[series].insert(msc_data)
            flash('Successfully added record.', 'success')
        return redirect(url_for('edit_record', series=series, number=number))
    if form.errors:
        flash('Could not save changes as there {:/was an error/were N errors}.'
              ' See below for details.'.format(Pluralizer(len(form.errors))),
              'error')
        for field, errors in form.errors.items():
            if len(errors) > 0:
                if isinstance(errors[0], str):
                    # Simple field
                    form[field].errors = clean_error_list(form[field])
                else:
                    # Subform
                    for subform in errors:
                        for subfield, suberrors in subform.items():
                            for f in form[field]:
                                f[subfield].errors = clean_error_list(f[subfield])
    return render_template(
        'edit-' + templates[series], form=form, doc_id=number, version=version,
        idSchemes=id_scheme_list, **params)


def clean_error_list(field):
    seen_errors = set()
    for error in field.errors:
        seen_errors.add(error)
    return list(seen_errors)


# Generic API contribution handling
# =================================
#
# Conformance checking function
# -----------------------------
def assess_conformance(series, document):
    """Examines the contents of an document and assesses its compliance with the
    MSC data model, giving the result as an integer score.

    Arguments:
        series (str): Record series
        document (dict or Document): MSC record

    Returns:
        dict: 'level' contains the conformance level of the record as an int,
            where 0 = invalid, 1 = valid, 2 = useful, and 3 = complete.
            'errors' contains any validation errors.
    """
    conformance = 0
    errors = dict()

    # Convert JSON into MultiDict format expected by WTForms
    converted = msc_to_form(document, padded=False)
    multi_dict_items = []
    for key in converted:
        value = converted[key]
        if isinstance(value, list):
            for index, subvalue in enumerate(value):
                if isinstance(subvalue, dict):
                    for subsubkey in subvalue:
                        multi_dict_items.append(
                            ('{}-{}-{}'.format(key, index, subsubkey),
                             subvalue[subsubkey]))
                elif isinstance(subvalue, list):
                    for subsubvalue in subvalue:
                        multi_dict_items.append(
                            ('{}-{}'.format(key, index), subvalue[subsubkey]))
                else:
                    multi_dict_items.append((key, subvalue))
        elif isinstance(value, dict):
            pass
        else:
            multi_dict_items.append((key, value))
    data = MultiDict(multi_dict_items)

    scheme_choices = get_choices('m')
    organization_choices = get_choices('g')

    # We'll use WTForms to validate the incoming JSON
    form = Forms[series](data, meta={'csrf': False})
    if series == 'm':
        # Validation for parent schemes
        form.parent_schemes.choices = scheme_choices
        # Validation for organizations
        form.maintainers.choices = organization_choices
        form.funders.choices = organization_choices
        form.users.choices = organization_choices
        # Validation for URL types
        for f in form.locations:
            f['type'].choices = scheme_locations
    elif series == 'g':
        # Validation for URL types
        for f in form.locations:
            f['type'].choices = organization_locations
    elif series == 't':
        # Validation for parent schemes
        form.supported_schemes.choices = scheme_choices
        # Validation for organizations
        form.maintainers.choices = organization_choices
        form.funders.choices = organization_choices
        # Validation for URL types
        for f in form.locations:
            f['type'].choices = tool_locations
    elif series == 'c':
        # Validation for parent schemes
        form.input_schemes.choices = scheme_choices
        form.output_schemes.choices = scheme_choices
        # Validation for organizations
        form.maintainers.choices = organization_choices
        form.funders.choices = organization_choices
        # Validation for URL types
        for f in form.locations:
            f['type'].validators.append(
                validators.Regexp(
                    mapping_location_regexp, message=mapping_location_help))
    elif series == 'e':
        # Validation for organizations
        form.originators.choices = organization_choices
        # Validation for URL types
        for f in form.locations:
            f['type'].choices = endorsement_locations

    form_fields = list()
    for unbound_field in Forms[series]._unbound_fields:
        form_fields.append(unbound_field[0])
    if form.validate():
        validity = 0
        utility = 1
        completeness = 1
        for field in form_fields:
            if field in converted:
                validity = 1
            else:
                completeness = 0
                if field in useful_fields[series]:
                    utility = 0
                    if validity:
                        break
        if validity:
            conformance = validity + utility + completeness
        else:
            errors['general'] = 'No valid fields supplied.'

    if form.errors:
        errors.update(form.errors)

    return {'level': conformance, 'errors': errors}


conformance_levels = ['invalid', 'valid', 'useful', 'complete']


# Generic record editing function
def create_or_update_record(series, number, document):
    mscid = None

    # Retrieve JSON payload
    new_record = request.get_json()

    # Validate JSON payload
    conformance = assess_conformance(series, new_record)
    if conformance['level'] == 0:
        return jsonify({
            'success': False,
            'errors': conformance['errors'],
            'conformance': conformance_levels[conformance['level']]})

    # Filter out MSCID if present
    if 'identifiers' in new_record:
        id_list = new_record['identifiers'].copy()
        new_record['identifiers'].clear()
        for identifier in id_list:
            if 'scheme' in identifier and identifier['scheme'] == 'RDA-MSCWG':
                if number:
                    mscid = get_mscid(series, number)
                    if 'id' in identifier and identifier['id'] != mscid:
                        abort(422)  # Throw error if MSCIDs do not match
                continue
            new_record['identifiers'].append(identifier)

    # Save record
    msc_data = fix_admin_data(new_record, series, number)
    if number:
        # Apply changes
        with transaction(tables[series]) as t:
            for key in (k for k in document if k not in msc_data):
                t.update_callable(delete(key), eids=[number])
            t.update(msc_data, eids=[number])
    else:
        # Insert new record
        number = tables[series].insert(msc_data)

    # Ensure consistency of dataType url/label pairs
    if series == 'm':
        with transaction(tables[series]) as t:
            if 'dataTypes' in msc_data:
                records_updated = propagate_data_types(
                    msc_data, tables[series], t)
            if 'versions' in msc_data:
                for version in msc_data:
                    if 'dataTypes' in version:
                        records_updated = propagate_data_types(
                            version, tables[series], t)

    if not mscid:
        mscid = get_mscid(series, number)

    # Return status, MSCID and conformance level
    return jsonify({
        'success': True,
        'id': mscid,
        'conformance': conformance_levels[conformance['level']]})


# CREATE function
@app.route('/api/<string(length=1):series>',
           methods=['POST'])
@auth.login_required
def create_record(series):
    if series not in table_names:
        abort(404)

    return create_or_update_record(series, 0, None)


# UPDATE function
@app.route('/api/<string(length=1):series><int:number>',
           methods=['PUT'])
@auth.login_required
def update_record(series, number):
    # Is this record in the database?
    if series not in table_names:
        abort(404)
    document = tables[series].get(doc_id=number)
    if not document:
        abort(404)

    return create_or_update_record(series, number, document)


# DELETE function
@app.route('/api/<string(length=1):series><int:number>',
           methods=['DELETE'])
@auth.login_required
def delete_record(series, number):
    # Is this record in the database?
    if series not in table_names:
        abort(404)
    document = tables[series].get(doc_id=number)
    if not document:
        abort(404)

    # tables[series].remove(doc_ids=[number])
    # Should this empty the record instead, properly to prevent re-use?
    with transaction(tables[series]) as t:
        for key in document:
            t.update_callable(delete(key), eids=[number])

    # Return status, MSCID and conformance level
    return jsonify({
        'success': True,
        'id': get_mscid(series, number)})


# GET function for one record
@app.route('/api/<string(length=1):series><int:number>',
           methods=['GET'])
@cross_origin()
def get_record(series, number):
    return display(series, number, api=True)


# GET function for all records in a series
@app.route('/api/<string(length=1):series>',
           methods=['GET'])
@cross_origin()
def list_records(series):
    if series not in table_names:
        abort(404)

    records = list()
    for record in tables[series].search(Query().slug.exists()):
        records.append({'id': record.doc_id, 'slug': record['slug']})

    return jsonify({table_names[series]: records})

# GET function for records by subject
@app.route('/api/subject-index',
            methods=['GET'])
@cross_origin()
def subject_index_api():
    full_keyword_uris = get_used_term_uris()
    domains = thesaurus.subjects(RDF.type, UNO.Domain)
    tree = get_term_tree(domains, filter=full_keyword_uris)
    tree.insert(0, {
        'name': 'Multidisciplinary',
        'url': url_for('subject', subject='Multidisciplinary')})
    return jsonify(tree)

# Automatic self-updating
# =======================
@webhook.hook()
def on_push(data):
    print("Upstream code repository has been updated.")
    print("Initiating git pull to update codebase.")
    call = subprocess.run(['git', 'pull', '--rebase'], stderr=subprocess.STDOUT)
    print("Git pull completed with exit code {}.".format(call.returncode))


# Executing
# =========
if __name__ == '__main__':
    app.run()
