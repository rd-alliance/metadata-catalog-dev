#! /usr/bin/python3

### Dependencies

## Standard

import os, sys, re

## Non-standard

# See http://flask.pocoo.org/docs/0.10/
# On Debian, Ubuntu, etc.:
#   - old version: sudo apt-get install python3-flask
#   - latest version: sudo -H pip3 install flask
from flask import Flask, request, url_for, render_template, flash, redirect, jsonify, g, session

# See https://pythonhosted.org/Flask-OpenID/
# Install from PyPi: sudo -H pip3 install Flask-OpenID
from flask.ext.openid import OpenID

# See http://tinydb.readthedocs.io/
# Install from PyPi: sudo -H pip3 install tinydb
from tinydb import TinyDB, Query, where

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
    slug = toSlug(term)
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

def toSlug(string):
    """Transforms string into URL-safe slug."""
    slug = string.replace(' ', '+')
    return slug

def fromSlug(slug):
    """Transforms URL-safe slug back into regular string."""
    string = slug.replace('+', ' ')
    return string

def wild2regex(string):
    """Transforms wildcard searches to regular expressions."""
    regex = re.escape(string)
    regex = regex.replace('\*','.*')
    regex = regex.replace('\?','.?')
    return regex

### Functions made available to templates

@app.context_processor
def utility_processor():
    return { 'toSlug': toSlug, 'fromSlug': fromSlug }

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

    if request_wants_json():
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
@app.route('/msc/t<int:number>/<field>')
def tool(number, field=None):
    tools = db.table('tools')
    element = tools.get(eid=number)

    if request_wants_json():
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
        raw_versions = element['versions']
        for v in raw_versions:
            if not 'number' in v:
                continue
            if not 'date' in v:
                continue
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

    if request_wants_json():
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

    if request_wants_json():
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

    if request_wants_json():
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
    query_string = fromSlug(subject)
    results = list()

    # Interpret subject
    term_list = list()
    if subject == 'multidisciplinary':
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
    query_string = fromSlug(dataType)
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
        'url': url_for('subject', subject='multidisciplinary')})
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
    flash('Setting session Open ID to {}.'.format(resp.identity_url))
    if 'openid' in session:
        flash('Session Open ID is now {}.'.format(session['openid']))
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

### Editing screen

@app.route('/edit/m<int:number>', methods=['GET', 'POST'])
def edit_scheme(number):
    if g.user is None:
        flash('You must sign in before making any changes.', 'error')
        return redirect(url_for('login'))
    schemes = db.table('metadata-schemes')
    organizations = db.table('organizations')
    element = schemes.get(eid=number)
    if request.method == 'POST':
        flash('Your edits were received but the gubbins for implementing them aren’t in place yet.')
        return redirect(url_for('scheme', number=number))
    else:
        if element:
            flash('You can edit this existing record using the form below.')
        else:
            flash('You can add a new record using the form below.')
            element = dict()
        # Title, identifier, funder, dataType help
        all_schemes = schemes.all()
        id_set = set()
        funder_set = set()
        type_set = set()
        for scheme in all_schemes:
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
        id_list = list(id_set)
        id_list.sort()
        funder_list = list(funder_set)
        funder_list.sort(key=lambda k: k.lower())
        type_list = list(type_set)
        type_list.sort(key=lambda k: k.lower())
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
        return render_template('edit-scheme.html', record=element, eid=number,\
            subjects=subject_list, dataTypes=type_list)

### Ajax form snippets


### Executing

if __name__ == '__main__':
    app.run(debug=True)
