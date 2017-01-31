#! /usr/bin/python3

### Dependencies

import argparse, os, sys, yaml, re, datetime

### Initializing

## Calculate defaults

default_source = os.path.realpath(os.path.join(os.path.dirname(sys.argv[0]), '..', 'metadata-directory'))
default_dest = os.path.realpath(os.path.join(os.path.dirname(sys.argv[0]), 'db'))
log_file = os.path.realpath(os.path.join(os.path.dirname(sys.argv[0]), 'migration-log.txt'))

## Command-line arguments

parser = argparse.ArgumentParser(description='''
Converts RDA metadata standards directory data into the new RDA metadata
standards catalog data model, ready for importing into a NoSQL database.''')
parser.add_argument('-f', '--from'\
    ,help='Location of MSD data files'\
    ,action='store'\
    ,default=default_source\
    ,dest='source')
parser.add_argument('-t', '--to'\
    ,help='Location of MSC data files'\
    ,action='store'\
    ,default=default_dest\
    ,dest='dest')
args = parser.parse_args()

## Utility functions

def getMSCID(path):
    if os.path.isfile(path):
        with open(path, 'r') as r:
            dest_records = yaml.safe_load_all(r)
            dest_record = next(dest_records)
            for identifier in dest_record['identifiers']:
                if identifier['scheme'] == 'RDA-MSCWG':
                    return identifier['id']
    else:
        return None

def loadRecord(path):
    if os.path.isfile(path):
        with open(path, 'r') as r:
            dest_records = yaml.safe_load_all(r)
            dest_record = next(dest_records)
            return dest_record
    else:
        return None

# TODO: define vocabulary mapping
def translateKeyword(kw):
    output = None
    return output

def createSlug(string):
    output = string.strip().lower().replace(' ', '-')
    output = re.sub(r'-+', '-', output)
    output = re.sub(r'[^-A-Za-z0-9_]+', '', output)
    return output

## Utility variables

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

# Log file contents
log = ''
isNewLog = False

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
for series, folder in { 'm': 'metadata-schemes', 'g': 'organizations', 't': 'tools', 'c': 'mappings', 'e': 'endorsements' }.items():
    if os.path.isdir(os.path.join(args.dest, folder)):
        serial_no = 0
        for entry in os.listdir(os.path.join(args.dest, folder)):
            if (os.path.splitext(entry)[1] != '.yml'):
                continue
            with open(os.path.join(args.dest, folder, entry), 'r') as r:
                dest_records = yaml.safe_load_all(r)
                dest_record = next(dest_records)
                for identifier in dest_record['identifiers']:
                    if identifier['scheme'] == 'RDA-MSCWG':
                        id_no = int(identifier['id'].replace('msc:' + series, ''))
                        if id_no > serial_no:
                            serial_no = id_no
                        break
        exec(series + ' = serial_no')
        print('Found {} up to msc:{}{}.'.format(folder, series, serial_no))
    else:
        print ('Subdirectory {} missing, creating...'.format(folder))
        os.makedirs(os.path.join(args.dest, folder))

# TODO: scan for existing data and reuse identifiers?

## Parsing data files

# Parsing standards
db_standards = dict()

print('Converting standards to MSC data model...')
for record in standards:
    slug = os.path.splitext(os.path.basename(record))[0]
    id_string = getMSCID(os.path.join(args.dest, 'metadata-schemes', slug + '.yml'))
    if not id_string:
        m += 1
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
                log += 'Standard {} includes version status {}.\n'.format(slug, source_record['status'])
                isNewLog = True
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

if isNewLog:
    log += '\n'
    isNewLog = False

# Parsing profiles
print('Converting profiles to MSC data model...')
for record in profiles:
    slug = os.path.splitext(os.path.basename(record))[0]
    id_string = getMSCID(os.path.join(args.dest, 'metadata-schemes', slug + '.yml'))
    if not id_string:
        m += 1
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
                    log += 'Extension {} contains reference to unknown parent standard {}.\n'.format(slug, standard)
                    isNewLog = True

    db_standards[slug] = dest_record

if isNewLog:
    log += '\n'
    isNewLog = False

# Parsing tool records
db_tools = dict()

print('Converting tools to MSC data model...')
for record in tools:
    slug = os.path.splitext(os.path.basename(record))[0]
    id_string = getMSCID(os.path.join(args.dest, 'tools', slug + '.yml'))
    if not id_string:
        t += 1
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
                    log += 'Tool {} contains reference to unknown standard {}.\n'.format(slug, standard)
                    isNewLog = True

    db_tools[slug] = dest_record

if isNewLog:
    log += '\n'
    isNewLog = False

# Parsing use case records
db_organizations = dict()

print('Converting use cases to MSC data model...')
for record in users:
    slug = os.path.splitext(os.path.basename(record))[0]
    id_string = getMSCID(os.path.join(args.dest, 'organizations', slug + '.yml'))
    if not id_string:
        g += 1
        id_string = 'msc:g{}'.format(g)
    g_index[slug] = id_string
    dest_record = dict()

    with open(record, 'r') as r:
        source_records = yaml.safe_load_all(r)
        source_record = next(source_records)
        if 'title' in source_record:
            dest_record['name'] = source_record['title']
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
        if 'standards' in source_record:
            for standard in source_record['standards']:
                if standard in m_index:
                    # Insert relation in other record
                    relation = { 'id': record_id, 'type': 'user' }
                    if not 'relatedEntities' in db_standards[standard]:
                        db_standards[standard]['relatedEntities'] = list()
                    db_standards[standard]['relatedEntities'].append(relation)
                else:
                    log += 'Use case {} contains reference to unknown standard {}.\n'.format(slug, standard)
                    isNewLog = True

    db_organizations[slug] = dest_record

if isNewLog:
    log += '\n'
    isNewLog = False

# Creating mappings records
db_mappings = dict()

try:
    mappings = sorted(mappings, key=lambda k: k['from'] + k['to'])
except KeyError:
    try:
        mappings = sorted(mappings, key=lambda k: k['from'] + k['url'])
    except KeyError:
        mappings = sorted(mappings, key=lambda k: k['from'])

print('Creating records for mappings...')
for mapping in mappings:
    slug = ''
    slug_from = mapping['from']
    slug += '-'.join(slug_from.split('-')[:3])
    slug += '_TO_'
    slug_to = createSlug(mapping['to'])
    slug += '-'.join(slug_to.split('-')[:3])
    id_string = getMSCID(os.path.join(args.dest, 'mappings', slug + '.yml'))
    if not id_string:
        c += 1
        id_string = 'msc:c{}'.format(c)
    dest_record = dict()

    record_id = { 'id': id_string, 'scheme': 'RDA-MSCWG' }
    dest_record['identifiers'] = [ record_id ]
    if 'url' in mapping:
        location = { 'url': mapping['url'], 'type': 'document' }
        dest_record['locations'] = [ location ]
    related = list()
    description = 'A mapping from '
    if 'from' in mapping:
        relation = dict()
        if slug_from in m_index:
            relation['id'] = m_index[slug_from]
            description += db_standards[slug_from]['title']
        else:
            log += 'Mapping encountered from unknown standard {}. There is a bug in the migration script.\n'.format(slug_from)
            isNewLog = True
            description += slug_from
        relation['type'] = 'input scheme'
        related.append(relation)
    if 'to' in mapping:
        relation = dict()
        name = mapping['to']
        description += ' to {}.'.format(name)
        if slug_to in m_index:
            relation['id'] = m_index[slug_to]
        else:
            to_id_string = getMSCID(os.path.join(args.dest, 'metadata-schemes', slug_to + '.yml'))
            if to_id_string:
                log += 'In standard {}, found mapping to unknown standard {} but stub already present.\n'.format(slug_from, slug_to)
                isNewLog = True
                relation['id'] = to_id_string
                m_index[slug_to] = to_id_string
                db_standards[slug_to] = loadRecord(os.path.join(args.dest, 'metadata-schemes', slug_to + '.yml'))
            else:
                # unknown scheme: create stub
                log += 'In standard {}, found mapping to unknown standard {} so created a stub.\n'.format(slug_from, slug_to)
                isNewLog = True
                m += 1
                standard_id_string = 'msc:m{}'.format(m)
                m_index[slug_to] = standard_id_string
                standard_record = dict()
                standard_record_id = { 'id': standard_id_string, 'scheme': 'RDA-MSCWG' }
                standard_record['identifiers'] = [ standard_record_id ]
                standard_record['title'] = name
                db_standards[slug_to] = standard_record
                relation['id'] = standard_id_string
        relation['type'] = 'output scheme'
        related.append(relation)
    dest_record['relatedEntities'] = related
    dest_record['description'] = description

    db_mappings[slug] = dest_record

if isNewLog:
    log += '\n'
    isNewLog = False

# Creating funder records
try:
    sponsors = sorted(sponsors, key=lambda k: k['standard'] + k['name'])
except KeyError:
    try:
        sponsors = sorted(sponsors, key=lambda k: k['standard'] + k['url'])
    except KeyError:
        sponsors = sorted(sponsors, key=lambda k: k['standard'])

print('Adding maintainer (sponsor) relationships...')
for sponsor in sponsors:
    standard = sponsor['standard']
    id_string = None
    slug = None
    if 'name' in sponsor:
        slug = createSlug(sponsor['name'])
        if slug in g_index:
            id_string = g_index[slug]
        else:
            id_string = getMSCID(os.path.join(args.dest, 'organizations', slug + '.yml'))
            if id_string:
                g_index[slug] = id_string
                db_organizations[slug] = loadRecord(os.path.join(args.dest, 'organizations', slug + '.yml'))
                log += 'In standard {}, found reference to unknown sponsor {} but stub already present.\n'.format(standard, slug)
                isNewLog = True
    else:
        if 'url' in sponsor:
            for org_slug, org in db_organizations:
                if 'locations' in org:
                    for location in org['locations']:
                        if 'url' in location:
                            if sponsor['url'] == location['url']:
                                org_ids = org['identifiers']
                                for org_id in org_ids:
                                    if 'scheme' in org_id and org_id['scheme'] == 'RDA-MSCWG':
                                        id_string = org_id['id']
                                        slug = org_slug
                                        break
                                        break
                                        break
    if (not id_string) and slug:
        # Need to create new record
        log += 'In standard {}, found reference to unknown sponsor {} so created a stub.\n'.format(standard, slug)
        isNewLog = True
        g += 1
        id_string = 'msc:g{}'.format(g)
        g_index[slug] = id_string
        dest_record = dict()
        dest_record['name'] = sponsor['name']
        record_id = { 'id': id_string, 'scheme': 'RDA-MSCWG' }
        dest_record['identifiers'] = [ record_id ]
        locations = list()
        if 'url' in sponsor:
            location = { 'url': sponsor['url'], 'type': 'website' }
            locations.append(location)
            dest_record['locations'] = locations
        db_organizations[slug] = dest_record
    if id_string:
        # We can add a cross-reference now
        relation = { 'id': id_string, 'type': 'funder' }
        if not 'relatedEntities' in db_standards[standard]:
            db_standards[standard]['relatedEntities'] = list()
        db_standards[standard]['relatedEntities'].append(relation)
    else:
        print('WARNING: incomplete sponsor information in {}.'.format(standard))

if isNewLog:
    log += '\n'
    isNewLog = False

# Creating contact records
try:
    contacts = sorted(contacts, key=lambda k: k['standard'] + k['name'])
except KeyError:
    try:
        contacts = sorted(contacts, key=lambda k: k['standard'] + k['email'])
    except KeyError:
        contacts = sorted(contacts, key=lambda k: k['standard'])

print('Adding maintainer (contact) relationships...')
for contact in contacts:
    standard = contact['standard']
    id_string = None
    slug = None
    if 'name' in contact:
        slug = createSlug(contact['name'])
        if slug in g_index:
            id_string = g_index[slug]
        else:
            id_string = getMSCID(os.path.join(args.dest, 'organizations', slug + '.yml'))
            if id_string:
                g_index[slug] = id_string
                db_organizations[slug] = loadRecord(os.path.join(args.dest, 'organizations', slug + '.yml'))
                log += 'In standard {}, found reference to unknown contact {} but stub already present.\n'.format(standard, slug)
                isNewLog = True
    else:
        if 'email' in contact:
            for org_slug, org in db_organizations:
                if 'locations' in org:
                    for location in org['locations']:
                        if 'url' in location:
                            if contact['email'] == location['url']:
                                org_ids = org['identifiers']
                                for org_id in org_ids:
                                    if 'scheme' in org_id and org_id['scheme'] == 'RDA-MSCWG':
                                        id_string = org_id['id']
                                        slug = org_slug
                                        break
                                        break
                                        break
    if (not id_string) and slug:
        # Need to create new record
        log += 'In standard {}, found reference to unknown contact {} so created a stub.\n'.format(standard, slug)
        isNewLog = True
        g += 1
        id_string = 'msc:g{}'.format(g)
        g_index[slug] = id_string
        dest_record = dict()
        dest_record['name'] = contact['name']
        record_id = { 'id': id_string, 'scheme': 'RDA-MSCWG' }
        dest_record['identifiers'] = [ record_id ]
        locations = list()
        if 'email' in contact:
            location = { 'url': contact['email'], 'type': 'email' }
            locations.append(location)
            dest_record['locations'] = locations
        db_organizations[slug] = dest_record
    if id_string and slug:
        # We can add a cross-reference now
        relation = { 'id': id_string, 'type': 'funder' }
        if not 'relatedEntities' in db_standards[standard]:
            db_standards[standard]['relatedEntities'] = list()
        db_standards[standard]['relatedEntities'].append(relation)
        # Add email address to org record if missing
        if 'email' in contact:
            if 'locations' in db_organizations[slug]:
                hasEmail = False
                for location in db_organizations[slug]['locations']:
                    if 'type' in location and location['type'] == 'email':
                        hasEmail = True
                if not hasEmail:
                    location = { 'url': contact['email'], 'type': 'email' }
                    db_organizations[slug]['locations'].append(location)
            else:
                db_organizations[slug]['locations'] = list()
                location = { 'url': contact['email'], 'type': 'email' }
                db_organizations[slug]['locations'].append(location)
    else:
        log += 'Standard {} has incomplete contact information.'.format(standard)
        isNewLog = True

if isNewLog:
    log += '\n'
    isNewLog = False

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
for slug, dest_record in db_organizations.items():
    new_record = os.path.join(args.dest, 'organizations', slug + '.yml')
    with open(new_record, 'w') as r:
        yaml.safe_dump(dest_record, r)
for slug, dest_record in db_mappings.items():
    new_record = os.path.join(args.dest, 'mappings', slug + '.yml')
    with open(new_record, 'w') as r:
        yaml.safe_dump(dest_record, r)

print('There were issues you should look at: see migration log.')
log = 'Migration log: {}\n\n'.format(datetime.datetime.now(datetime.timezone.utc).isoformat(' ')) + log
if log:
    with open(log_file, 'w') as l:
        l.write(log)

print('Finished!')
