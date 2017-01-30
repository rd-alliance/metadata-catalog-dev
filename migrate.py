#! /usr/bin/python3

### Dependencies

import argparse, os, sys, yaml

### Initializing

## Calculate defaults

default_source = os.path.realpath(os.path.join(os.path.dirname(sys.argv[0]), '..', 'metadata-directory'))
default_dest = os.path.realpath(os.path.join(os.path.dirname(sys.argv[0]), 'db'))

## Command-line arguments

parser = argparse.ArgumentParser(description='''
Converts RDA metadata standards directory data into the new RDA metadata standards catalog model.''')
parser.add_argument('-f', '--from'\
    ,help='Path of MSD data files'\
    ,action='store'\
    ,default=default_source\
    ,dest='source')
parser.add_argument('-t', '--to'\
    ,help='Path of MSC data files'\
    ,action='store'\
    ,default=default_dest\
    ,dest='dest')
args = parser.parse_args()

### Processing

## Locating data files

print('Scanning {} for data files...'.format(args.source))

def getRecords(folder):
    output = list()
    if os.path.isdir(os.path.join(args.source, folder)):
        for entry in os.listdir(os.path.join(args.source, folder)):
            if (entry == 'add.md' or entry == 'index.md'):
                continue
            if (os.path.splitext(entry)[1] != '.md'):
                continue
            output.append(os.path.join(args.source, folder, entry))
        # DEBUG
        print('Subdirectory "{}": found {} records.'.format(folder, len(output)))
    else:
        print('Subdirectory "{}" missing, skipping...'.format(folder))
    output.sort()
    return output

standards = getRecords('standards')
profiles = getRecords('extensions')
tools = getRecords('tools')
users = getRecords('use_cases')

print('Checking {} for data structure...'.format(args.dest))
for folder in [ 'metadata-schemes', 'organizations', 'tools', 'mappings', 'endorsements' ]:
    if not os.path.isdir(os.path.join(args.dest, folder)):
        print ('Subdirectory {} missing, creating...'.format(folder))
        os.mkdir(os.path.join(args.dest, folder))

## Utility functions

def translateKeyword(kw):
    output = None
    return output

## Parsing data files

# Lookup for slug -> new ID
m_index = dict()
g_index = dict()
t_index = dict()

# Collecting information for post-processing
mappings = list()
sponsors = list()
contacts = list()

# Incremental ID integers
m = 0
g = 0
t = 0
c = 0
e = 0

# Parsing standards
record = standards[0]
slug = os.path.splitext(os.path.basename(record))[0]
m += 1
m_index[slug] = 'msc:m{}'.format(m)
dest_record = dict()

with open(record, 'r') as r:
    source_records = yaml.safe_load_all(r)
    source_record = next(source_records)
    if 'title' in source_record:
        dest_record['title'] = source_record['title']
    record_id = { 'id': 'msc:m{}'.format(m), 'scheme': 'RDA-MSCWG' }
    dest_record['identifiers'] = [ record_id ]
    if 'version' in source_record:
        version = { 'number': source_record['version'] }
        if 'status' in source_record:
            print('Check {} for how to handle status {}'.format(slug, source_record['status']))
        if 'standard_update_date' in source_record:
            version['issued'] = source_record['standard_update_date']
        dest_record['versions'] = [ version ]
    if 'description' in source_record:
        dest_record['description'] = source_record['description']
    if 'disciplines' in source_record:
        keywords = list()
        for discipine in source_record['disciplines']:
            kw = translateKeyword(discipine)
            if kw:
                keywords.append(kw)
        if len(keywords) == 0:
            keywords.append('multidisciplinary')
        dest_record['keywords'] = keywords
    locations = list()
    if 'specification_url' in source_record:
        location = { 'url': source_record['specification_url'], 'type': 'document' }
        locations.append(location)
    if 'website' in source_record:
        location = { 'url': source_record['website'], 'type': 'website' }
        locations.append(location)
    if len(locations) > 0:
        dest_record['locations'] = locations
    # The following will be implemented as relations at the end.
    if 'mappings' in source_record:
        for mapping in source_record['mappings']:
            crosswalk = { 'from': slug }
            if 'name' in mapping:
                crosswalk['to'] = mapping['name']
            if 'url' in mapping:
                crosswalk['url'] = mapping['url']
            mappings.append(crosswalk)
    if 'sponsors' in source_record:
        for sponsor in source_record['sponsors']:
            org = { 'standard': slug }
            if 'name' in sponsor:
                org['name'] = sponsor['name']
            if 'url' in sponsor:
                org['url'] = sponsor['url']
            sponsors.append(org)
    if 'contact' in source_record:
        org = { 'standard': slug, 'name': source_record['contact'] }
        if 'contact_email' in source_record:
            org['email'] = source_record['contact_email']
        contacts.append(org)

new_record = os.path.join(args.dest, 'metadata-schemes', slug + '.yml')
with open(new_record, 'w') as r:
    yaml.safe_dump(dest_record, r)
