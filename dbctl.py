#! /usr/bin/python3

### Dependencies

## Standard

import argparse, os, sys, json, re
from datetime import date

## Non-standard

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

### Initializing

## Calculate defaults

script_dir = os.path.dirname(sys.argv[0])

default_folder = os.path.realpath(os.path.join(script_dir, 'db'))
default_file = os.path.realpath(os.path.join(script_dir, 'db.json'))

subfolders = {'endorsements': 'e',
    'mappings': 'c',
    'metadata-schemes': 'm',
    'organizations': 'g',
    'tools': 't'}

## Command-line arguments

parser = argparse.ArgumentParser(description='''
Converts a collection of YAML files into TinyDB database or vice versa. The
YAML files should be arranged in subfolders according to type, i.e. {}.'''.format(\
    ', '.join(sorted(subfolders))))
parser.add_argument('-f', '--folder'\
    ,help='location of YAML data file collection (default: ./db/)'\
    ,action='store'\
    ,default=default_folder\
    ,dest='folder')
parser.add_argument('-d', '--db'\
    ,help='location of TinyDB JSON data file (default: ./db.json)'\
    ,action='store'\
    ,default=default_file\
    ,dest='file')
subparsers = parser.add_subparsers(title='subcommands', help='perform database operation')
parser_compile = subparsers.add_parser('compile', help='compile YAML files to TinyDB database')
parser_dump = subparsers.add_parser('dump', help='dump TinyDB database to YAML files')
parser_vocab = subparsers.add_parser('vocab', help='fetch and optimise UNESCO Vocabulary')

### Operations

## Compilation

def json_serial(obj):
    """JSON serializer for objects not serializable by default json code"""

    if isinstance(obj, date):
        serial = obj.isoformat()
        return serial
    raise TypeError ("Type not serializable")

def dbCompile(args):
    if not os.path.isdir(args.folder):
        print('Cannot find YAML files; please check folder location and try again.')
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
            print('WARNING: Expected to find {} folder but it is missing.'.format(folder))
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
            if len(id_list) > 0:
                record['identifiers'] = id_list
            else:
                del record['identifiers']
            db[folder][id_number] = record

        isCompiled = True

    if isCompiled:
        with open(args.file, 'w') as f:
            json.dump(db, f, default=json_serial, sort_keys=True)
    else:
        print('No data files found, database not created.')

parser_compile.set_defaults(func=dbCompile)

## Dump to files

def createSlug(string):
    output = string.strip().lower().replace(' ', '-')
    output = re.sub(r'-+', '-', output)
    output = re.sub(r'[^-A-Za-z0-9_]+', '', output)
    return output

def dbDump(args):
    if not os.path.isfile(args.file):
        print('Cannot find database file; please check location and try again.')
        sys.exit(1)

    if os.path.isdir(args.folder):
        print('Database folder already exists at {}.'.format(args.file))
        print('Do you wish to erase it, back it up, or keep it? [e(rase)/(b)ackup/K(eep)]')
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
                os.rename(os.path.join(args.folder + str(i), 'README.md'),\
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
                record['relatedEntities'].sort(key=lambda k: k['id'][:5] + k['id'][5:].zfill(5))
            if 'identifiers' not in record:
                record['identifiers'] = list()
            record['identifiers'].insert(0,\
                {'id': 'msc:{}{}'.format(series, record.eid),\
                    'scheme': 'RDA-MSCWG'})
            dumped_record = os.path.join(folder_path, slug + '.yml')
            with open(dumped_record, 'w') as r:
                yaml.safe_dump(dict(record), r, default_flow_style=False,
                               allow_unicode=True)

parser_dump.set_defaults(func=dbDump)

### Vocabulary generation

def dbVocab(args):
    thesaurus = rdflib.Graph()
    if os.path.isfile(os.path.join(script_dir, 'unesco-thesaurus.ttl')):
        print('Loading UNESCO Vocabulary from local file.')
        thesaurus.parse('unesco-thesaurus.ttl', format='turtle')
    else:
        print('Loading UNESCO Vocabulary from the Internet.')
        thesaurus.parse(r'http://vocabularies.unesco.org/browser/rest/v1/thesaurus/data?format=text/turtle', format='turtle')

    thesaurus.parse('unesco-thesaurus.ttl', format='turtle')
    simplified = rdflib.Graph(namespace_manager=thesaurus.namespace_manager)
    simplified.bind('uno', 'http://vocabularies.unesco.org/ontology#')
    UNO = Namespace('http://vocabularies.unesco.org/ontology#')

    print('Cherry-picking the triples used by the app...')
    # We want the labels and types
    simplified += thesaurus.triples( (None, SKOS.prefLabel, None) )
    # simplified += thesaurus.triples( (None, SKOS.altLabel, None) ) # Not yet, but planned
    simplified += thesaurus.triples( (None, RDF.type, SKOS.Concept) )
    simplified += thesaurus.triples( (None, RDF.type, UNO.MicroThesaurus) )
    simplified += thesaurus.triples( (None, RDF.type, UNO.Domain) )

    # Among the concepts, these are the ones we use
    simplified += thesaurus.triples( (None, SKOS.broader, None) )
    simplified += thesaurus.triples( (None, SKOS.narrower, None) )

    # We convert domains to top-level concepts
    for s, p, o in thesaurus.triples( (None, SKOS.member, None) ):
        if (o, RDF.type, SKOS.Concept) in thesaurus\
            and not (o, SKOS.topConceptOf, URIRef('http://vocabularies.unesco.org/thesaurus')) in thesaurus:
            continue
        simplified.add( (s, SKOS.narrower, o) )
        simplified.add( (o, SKOS.broader, s) )

    print('Writing simplified thesaurus.')
    simplified.serialize('simple-unesco-thesaurus.ttl', format='turtle')

parser_vocab.set_defaults(func=dbVocab)

### Processing

args = parser.parse_args()
args.func(args)
