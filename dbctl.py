#! /usr/bin/python3

# Dependencies
# ============

# Standard
# --------

import argparse
import os
import sys
import json
import re
from datetime import date

# Non-standard
# ------------

import yaml

# See http://tinydb.readthedocs.io/en/latest/intro.html
# Install from PyPi: sudo pip3 install tinydb
# sudo apt install python3-ujson
from tinydb import TinyDB

# See http://rdflib.readthedocs.io/
# On Debian, Ubuntu, etc.:
#   - old version: sudo apt-get install python3-rdflib
#   - latest version: sudo pip3 install rdflib
import rdflib
from rdflib import Literal, Namespace, URIRef
from rdflib.namespace import SKOS, RDF

# Initializing
# ============

# Calculate defaults
# ------------------

script_dir = os.path.dirname(sys.argv[0])

default_folder = os.path.realpath(os.path.join(script_dir, 'db'))
default_file = os.path.realpath(os.path.join(script_dir, 'db.json'))

subfolders = {
    'endorsements': 'e',
    'mappings': 'c',
    'metadata-schemes': 'm',
    'organizations': 'g',
    'tools': 't'}

# Command-line arguments
# ----------------------

parser = argparse.ArgumentParser(
    description='Converts a collection of YAML files into TinyDB database or'
                ' vice versa. The YAML files should be arranged in subfolders'
                ' according to type, i.e. {}.'
                ''.format(', '.join(sorted(subfolders))))
parser.add_argument(
    '-f', '--folder',
    help='location of YAML data file collection (default: ./db/)',
    action='store',
    default=default_folder,
    dest='folder')
parser.add_argument(
    '-d', '--db',
    help='location of TinyDB JSON data file (default: ./db.json)',
    action='store',
    default=default_file,
    dest='file')
subparsers = parser.add_subparsers(
    title='subcommands',
    help='perform database operation')
parser_checkids = subparsers.add_parser(
    'check-ids',
    help='check for and fix empty/missing IDs in sequence')
parser_compile = subparsers.add_parser(
    'compile',
    help='compile YAML files to TinyDB database')
parser_dump = subparsers.add_parser(
    'dump',
    help='dump TinyDB database to YAML files')
parser_vocab = subparsers.add_parser(
    'vocab',
    help='fetch and optimise UNESCO Vocabulary')

# Operations
# ==========


def json_serial(obj):
    """JSON serializer for objects not serializable by default json code."""

    if isinstance(obj, date):
        serial = obj.isoformat()
        return serial
    raise TypeError("Type not serializable")


def scan_ids(args):
    if not os.path.isdir(args.folder):
        print('Cannot find YAML files; please check folder location and try'
              ' again.')
        sys.exit(1)

    missing_ids = list()

    for folder in sorted(subfolders):
        folder_path = os.path.join(args.folder, folder)
        if not os.path.isdir(folder_path):
            print('WARNING: Expected to find {} folder but it is missing.'
                  ''.format(folder))
            continue

        highest_eid = 0
        eid_list = list()

        for entry in os.listdir(folder_path):
            name_tuple = os.path.splitext(entry)
            if (name_tuple[1] != '.yml'):
                continue

            slug = name_tuple[0]
            id_number = ''
            with open(os.path.join(folder_path, entry), 'r') as r:
                record = yaml.safe_load(r)
            id_list = list()
            for identifier in record['identifiers']:
                if identifier['scheme'] == 'RDA-MSCWG':
                    id_string = identifier['id']
                    id_number = id_string[5:]
            if not id_number:
                print('WARNING: {}/{} has no identifier.'.format(folder, slug))
                continue
            eid = int(id_number)
            if eid > highest_eid:
                highest_eid = eid
            eid_list.append(eid)

        series = subfolders[folder]
        for eid in range(1, highest_eid):
            if eid not in eid_list:
                missing_ids.append('msc:{}{}'.format(series, eid))

    return missing_ids


def fix_ids(args, missing_ids):
    if not missing_ids:
        return None

    # Create list of folders with non-sequential IDs.
    series_map = {v: k for k, v in subfolders.items()}
    bad_folders = set()
    for id_string in missing_ids:
        series = id_string[4:5]
        id_number = id_string[5:]
        bad_folders.add(series_map[series])

    # Populate database using slugs as unique keys.
    db = dict()
    for folder in sorted(subfolders):
        folder_path = os.path.join(args.folder, folder)
        if not os.path.isdir(folder_path):
            continue

        db[folder] = dict()

        for entry in os.listdir(folder_path):
            name_tuple = os.path.splitext(entry)
            if (name_tuple[1] != '.yml'):
                continue
            slug = name_tuple[0]

            with open(os.path.join(folder_path, entry), 'r') as r:
                record = yaml.safe_load(r)

            db[folder][slug] = record

    # Create mappings from old (non-sequential) IDs to new (sequential) IDs.
    id_map = dict()
    for folder in bad_folders:
        folder_path = os.path.join(args.folder, folder)
        records = db[folder]

        # Put slugs in the order in which they will be assigned IDs.
        slugs = list()
        if folder == 'metadata-schemes':
            standards = list()
            profiles = list()
            stubs = list()
            for slug, record in records.items():
                if 'relatedEntities' in record:
                    for entity in record['relatedEntities']:
                        if entity['role'] == 'parent scheme':
                            profiles.append(slug)
                            break
                    else:
                        standards.append(slug)
                elif 'description' not in record:
                    stubs.append(slug)
                else:
                    standards.append(slug)
            standards.sort()
            profiles.sort()
            stubs.sort()
            slugs.extend(standards)
            slugs.extend(profiles)
            slugs.extend(stubs)
        else:
            slugs = sorted(db[folder])
            slugs.sort()

        # For each slug, discover current ID, and change and map to new ID.
        i = 0
        for slug in slugs:
            i += 1
            record = records[slug]
            id_list = list()
            for identifier in record['identifiers']:
                if identifier['scheme'] == 'RDA-MSCWG':
                    current_id = identifier['id']
                    new_id = 'msc:{}{}'.format(subfolders[folder], i)
                    if current_id != new_id:
                        id_map[current_id] = new_id
                        identifier['id'] = new_id
                id_list.append(identifier)
            db[folder][slug]['identifiers'] = id_list

    # Now the ID map is finalized, go through *every* record and apply it
    # to relatedEntities cross-references, then write to disk.
    for folder in sorted(subfolders):
        folder_path = os.path.join(args.folder, folder)
        if not os.path.isdir(folder_path):
            continue

        # Go through the records in turn and change IDs wherever found
        if folder != 'organizations':
            # Organization records do not have relatedEntities
            records = db[folder]
            for slug, record in records.items():
                if 'relatedEntities' in record:
                    entity_list = list()
                    for entity in record['relatedEntities']:
                        if entity['id'] in id_map:
                            entity['id'] = id_map[entity['id']]
                        entity_list.append(entity)
                    db[folder][slug]['relatedEntities'] = entity_list

        # Now go through again and write to files
        for slug, record in db[folder].items():
            record_path = os.path.join(folder_path, '{}.yml'.format(slug))
            with open(record_path, 'w') as r:
                yaml.safe_dump(
                    dict(record), r, default_flow_style=False,
                    allow_unicode=True)


def dbCheckids(args):
    missing_ids = scan_ids(args)

    if missing_ids:
        for id_string in missing_ids:
            print('Identifier {} is missing from the sequence.'
                  ''.format(id_string))
        print('Do you wish to correct these issues? [y/N]')
        reply = input("> ")
        if reply[:1].lower() != 'y':
            print('Okay. I will leave things alone.')
            sys.exit(0)
        fix_ids(args, missing_ids)
    else:
        print('All identifiers are in sequence. It is safe to compile the'
              ' database.')

parser_checkids.set_defaults(func=dbCheckids)

# Compilation
# -----------


def dbCompile(args):
    if not os.path.isdir(args.folder):
        print('Cannot find YAML files; please check folder location and try'
              ' again.')
        sys.exit(1)

    missing_ids = scan_ids(args)
    if missing_ids:
        print('Database has missing IDs. Run "{}" to fix problem.'
              ''.format(parser_checkids.prog))
        sys.exit(1)

    if os.path.isfile(args.file):
        print('Database file already exists at {}.'.format(args.file))
        print('Do you wish to replace it? [y/N]')
        reply = input("> ")
        if reply[:1].lower() != 'y':
            print('Okay. I will leave it alone.')
            sys.exit(0)

    isCompiled = False
    db = dict()

    for folder in subfolders:
        folder_path = os.path.join(args.folder, folder)
        if not os.path.isdir(folder_path):
            continue

        db[folder] = dict()

        for entry in os.listdir(folder_path):
            if (os.path.splitext(entry)[1] != '.yml'):
                continue

            with open(os.path.join(folder_path, entry), 'r') as r:
                record = yaml.safe_load(r)
            record['slug'] = os.path.splitext(entry)[0]
            id_list = list()
            for identifier in record['identifiers']:
                if identifier['scheme'] == 'RDA-MSCWG':
                    id_string = identifier['id']
                    id_number = id_string[5:]
                else:
                    id_list.append(identifier)
            if id_list:
                record['identifiers'] = id_list
            else:
                del record['identifiers']
            for key in ['keywords', 'dataTypes']:
                if key in record:
                    term_set = set()
                    for term in record[key]:
                        term_set.add(term)
                    terms = list(term_set)
                    terms.sort()
                    record[key] = terms
            db[folder][id_number] = record

        isCompiled = True

    if isCompiled:
        with open(args.file, 'w') as f:
            json.dump(db, f, default=json_serial, sort_keys=True)
    else:
        print('No data files found, database not created.')

parser_compile.set_defaults(func=dbCompile)

# Dump to files
# -------------


def createSlug(string):
    output = string.strip().lower().replace(' ', '-')
    output = re.sub(r'-+', '-', output)
    output = re.sub(r'[^-A-Za-z0-9_]+', '', output)
    return output


def dbDump(args):
    if not os.path.isfile(args.file):
        print('Cannot find database file; please check location and try'
              ' again.')
        sys.exit(1)

    if os.path.isdir(args.folder):
        print('Database folder already exists at {}.'.format(args.file))
        print('Do you wish to erase it, back it up, or keep it?'
              ' [e(rase)/(b)ackup/K(eep)]')
        reply = input("> ")
        if reply[:1].lower() == 'e':
            for folder in sorted(subfolders):
                folder_path = os.path.join(args.folder, folder)
                if not os.path.isdir(folder_path):
                    continue
                for entry in os.listdir(folder_path):
                    if (os.path.splitext(entry)[1] == '.yml'):
                        os.remove(os.path.join(folder_path, entry))
        elif reply[:1].lower() == 'b':
            i = 0
            while os.path.isdir(args.folder + str(i)):
                i += 1
            else:
                os.rename(args.folder, args.folder + str(i))
                os.makedirs(args.folder)
                os.rename(os.path.join(args.folder + str(i), 'README.md'),
                          os.path.join(args.folder, 'README.md'))
        else:
            print('Okay. I will leave it alone.')
            sys.exit(0)

    db = TinyDB(args.file)

    for folder, series in subfolders.items():
        folder_path = os.path.join(args.folder, folder)
        if not os.path.isdir(folder_path):
            os.makedirs(folder_path)
        tbl = db.table(folder)
        records = tbl.all()
        for record in records:
            slug = record['slug']
            del record['slug']
            if 'relatedEntities' in record:
                record['relatedEntities'].sort(
                    key=lambda k: k['id'][:5] + k['id'][5:].zfill(5))
            if 'identifiers' not in record:
                record['identifiers'] = list()
            record['identifiers'].insert(
                0, {'id': 'msc:{}{}'.format(series, record.eid),
                    'scheme': 'RDA-MSCWG'})
            dumped_record = os.path.join(folder_path, slug + '.yml')
            with open(dumped_record, 'w') as r:
                yaml.safe_dump(dict(record), r, default_flow_style=False,
                               allow_unicode=True)

parser_dump.set_defaults(func=dbDump)

# Vocabulary generation
# ---------------------


def dbVocab(args):
    thesaurus = rdflib.Graph()
    if os.path.isfile(os.path.join(script_dir, 'unesco-thesaurus.ttl')):
        print('Loading UNESCO Vocabulary from local file.')
        thesaurus.parse('unesco-thesaurus.ttl', format='turtle')
    else:
        print('Loading UNESCO Vocabulary from the Internet.')
        thesaurus.parse(r'http://vocabularies.unesco.org/browser/rest/v1/'
                        'thesaurus/data?format=text/turtle', format='turtle')

    thesaurus.parse('unesco-thesaurus.ttl', format='turtle')
    simplified = rdflib.Graph(namespace_manager=thesaurus.namespace_manager)
    simplified.bind('uno', 'http://vocabularies.unesco.org/ontology#')
    UNO = Namespace('http://vocabularies.unesco.org/ontology#')

    print('Cherry-picking the triples used by the app...')
    # We want the labels and types
    simplified += thesaurus.triples((None, SKOS.prefLabel, None))
    # Not yet, but planned:
    # simplified += thesaurus.triples((None, SKOS.altLabel, None))
    simplified += thesaurus.triples((None, RDF.type, SKOS.Concept))
    simplified += thesaurus.triples((None, RDF.type, UNO.MicroThesaurus))
    simplified += thesaurus.triples((None, RDF.type, UNO.Domain))

    # Among the concepts, these are the ones we use
    simplified += thesaurus.triples((None, SKOS.broader, None))
    simplified += thesaurus.triples((None, SKOS.narrower, None))

    # We convert domains to top-level concepts
    for s, p, o in thesaurus.triples((None, SKOS.member, None)):
        if (o, RDF.type, SKOS.Concept) in thesaurus and (
                o, SKOS.topConceptOf, URIRef(
                    'http://vocabularies.unesco.org/thesaurus')) not in\
                thesaurus:
            continue
        simplified.add((s, SKOS.narrower, o))
        simplified.add((o, SKOS.broader, s))

    print('Writing simplified thesaurus.')
    simplified.serialize('simple-unesco-thesaurus.ttl', format='turtle')

parser_vocab.set_defaults(func=dbVocab)

# Processing
# ==========

args = parser.parse_args()
args.func(args)
