#! /usr/bin/python3

### Dependencies

import argparse, os, sys, yaml, re

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

# TODO: define vocabulary mapping
def translateKeyword(kw):
    output = None
    return output

def createSlug(string):
    output = string.strip().lower().replace(' ', '-')
    output = re.sub(r'-+', '-', output)
    output = re.sub(r'[^-A-Za-z0-9_]+', '', output)
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
db_standards = dict()

print('Converting standards to MSC data model...')
for record in standards:
    m += 1
    slug = os.path.splitext(os.path.basename(record))[0]
    id_string = 'msc:m{}'.format(m)
    m_index[slug] = id_string
    dest_record = dict()

    with open(record, 'r') as r:
        source_records = yaml.safe_load_all(r)
        source_record = next(source_records)
        if 'title' in source_record:
            dest_record['title'] = source_record['title']
        record_id = { 'id': id_string, 'scheme': 'RDA-MSCWG' }
        dest_record['identifiers'] = [ record_id ]
        if 'version' in source_record:
            version = { 'number': source_record['version'] }
            if 'status' in source_record:
                print('WARNING: check {} for how to handle status {}'.format(slug, source_record['status']))
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

    db_standards[slug] = dest_record

# Parsing profiles
print('Converting profiles to MSC data model...')
for record in profiles:
    m += 1
    slug = os.path.splitext(os.path.basename(record))[0]
    id_string = 'msc:m{}'.format(m)
    m_index[slug] = id_string
    dest_record = dict()

    with open(record, 'r') as r:
        source_records = yaml.safe_load_all(r)
        source_record = next(source_records)
        if 'title' in source_record:
            dest_record['title'] = source_record['title']
        record_id = { 'id': id_string, 'scheme': 'RDA-MSCWG' }
        dest_record['identifiers'] = [ record_id ]
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
        if 'website' in source_record:
            location = { 'url': source_record['website'], 'type': 'website' }
            locations.append(location)
        if len(locations) > 0:
            dest_record['locations'] = locations
        dest_record['relatedEntities'] = list()
        if 'standards' in source_record:
            for standard in source_record['standards']:
                if standard in m_index:
                    parent = { 'id': m_index[standard], 'role': 'parent scheme' }
                    dest_record['relatedEntities'].append(parent)
                else:
                    print('WARNING: unknown slug {} in profile {}.'.format(standard, slug))

    db_standards[slug] = dest_record

# Parsing tool records
db_tools = dict()

print('Converting tools to MSC data model...')
for record in tools:
    t += 1
    slug = os.path.splitext(os.path.basename(record))[0]
    id_string = 'msc:t{}'.format(t)
    t_index[slug] = id_string
    dest_record = dict()

    with open(record, 'r') as r:
        source_records = yaml.safe_load_all(r)
        source_record = next(source_records)
        if 'title' in source_record:
            dest_record['title'] = source_record['title']
        record_id = { 'id': id_string, 'scheme': 'RDA-MSCWG' }
        dest_record['identifiers'] = [ record_id ]
        if 'description' in source_record:
            dest_record['description'] = source_record['description']
        locations = list()
        if 'website' in source_record:
            location = { 'url': source_record['website'], 'type': 'website' }
            locations.append(location)
        if len(locations) > 0:
            dest_record['locations'] = locations
        dest_record['relatedEntities'] = list()
        if 'standards' in source_record:
            for standard in source_record['standards']:
                if standard in m_index:
                    supported = { 'id': m_index[standard], 'role': 'supported scheme' }
                    dest_record['relatedEntities'].append(supported)
                else:
                    print('WARNING: unknown slug {} in tool {}.'.format(standard, slug))

    db_tools[slug] = dest_record

# Creating mappings records
db_mappings = dict()

print('Creating records for mappings...')
for mapping in mappings:
    c += 1
    dest_record = dict()
    id_string = 'msc:c{}'.format(c)
    
    record_id = { 'id': id_string, 'scheme': 'RDA-MSCWG' }
    dest_record['identifiers'] = [ record_id ]
    if 'url' in mapping:
        location = { 'url': mapping['url'], 'type': 'document' }
        dest_record['locations'] = [ location ]
    related = list()
    description = 'A mapping from '
    if 'from' in mapping:
        relation = dict()
        slug = mapping['from']
        if slug in m_index:
            relation['id'] = m_index[slug]
            description += db_standards[slug]['title']
        else:
            print('WARNING: unknown slug {} in mapping'.format(slug))
            description += slug
        relation['type'] = 'input scheme'
        related.append(relation)
    if 'to' in mapping:
        relation = dict()
        name = mapping['to']
        slug = createSlug(name)
        description += ' to {}.'.format(name)
        if slug in m_index:
            relation['id'] = m_index[slug]
        else:
            # unknown scheme: create stub
            print('INFO: creating stub for {}. Is this right?'.format(slug))
            m += 1
            standard_id_string = 'msc:m{}'.format(m)
            m_index[slug] = standard_id_string
            standard_record = dict()
            standard_record_id = { 'id': standard_id_string, 'scheme': 'RDA-MSCWG' }
            standard_record['identifiers'] = [ standard_record_id ]
            standard_record['title'] = name
            db_standards[slug] = standard_record
            relation['id'] = standard_id_string
        relation['type'] = 'output scheme'
        related.append(relation)
    dest_record['relatedEntities'] = related
    dest_record['description'] = description

    db_mappings[id_string] = dest_record

# TODO: implemement sponsors/contacts as relations

## Writing migrated data to files

print('Writing out new records...')
for slug, dest_record in db_standards.items():
    new_record = os.path.join(args.dest, 'metadata-schemes', slug + '.yml')
    with open(new_record, 'w') as r:
        yaml.safe_dump(dest_record, r)
for slug, dest_record in db_tools.items():
    new_record = os.path.join(args.dest, 'tools', slug + '.yml')
    with open(new_record, 'w') as r:
        yaml.safe_dump(dest_record, r)
for id_string, dest_record in db_mappings.items():
    fn = id_string.replace(':', '-') + '.yml'
    new_record = os.path.join(args.dest, 'mappings', fn)
    with open(new_record, 'w') as r:
        yaml.safe_dump(dest_record, r)

print('Finished!')
