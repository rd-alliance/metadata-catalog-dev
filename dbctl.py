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

### Initializing

## Calculate defaults

script_dir = os.path.dirname(sys.argv[0])

default_folder = os.path.realpath(os.path.join(script_dir, 'db'))
default_file = os.path.realpath(os.path.join(script_dir, 'db.json'))

subfolders = ['endorsements', 'mappings', 'metadata-schemes', 'organizations', 'tools']

## Command-line arguments

parser = argparse.ArgumentParser(description='''
Converts a collection of YAML files into TinyDB database or vice versa. The
YAML files should be arranged in subfolders according to type, i.e. {}.'''.format(\
    ', '.join(subfolders)))
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
            for identifier in record['identifiers']:
                if identifier['scheme'] == 'RDA-MSCWG':
                    id_string = identifier['id']
                    id_number = id_string[5:]
                    break
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
            for folder in subfolders:
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
        else:
            print('Okay. I will leave it alone.')
            sys.exit(0)

    db = TinyDB(args.file)

    for folder in subfolders:
        folder_path = os.path.join(args.folder, folder)
        if not os.path.isdir(folder_path):
            os.makedirs(folder_path)
        tbl = db.table(folder)
        records = tbl.all()
        for record in records:
            slug = record['slug']
            dumped_record = os.path.join(folder_path, slug + '.yml')
            with open(dumped_record, 'w') as r:
                yaml.safe_dump(dict(record), r, default_flow_style=False)

parser_dump.set_defaults(func=dbDump)

### Processing

args = parser.parse_args()
args.func(args)
