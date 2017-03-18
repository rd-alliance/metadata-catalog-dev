#! /usr/bin/python3

# Dependencies
# ============

# Standard
# --------
import argparse
import os
import sys
import re
import datetime

# Non-standard
# ------------
import yaml

# Initializing
# ============

# Calculate defaults
# ------------------
script_dir = os.path.dirname(sys.argv[0])

default_source = os.path.realpath(
    os.path.join(script_dir, '..', 'metadata-directory'))
default_dest = os.path.realpath(os.path.join(script_dir, 'db'))
kw_mapping = os.path.realpath(os.path.join(script_dir, 'jacs2unesco.yml'))

log_file = os.path.realpath(os.path.join(script_dir, 'migration-log.txt'))
kw_file = os.path.realpath(os.path.join(script_dir, 'disciplines.yml'))

# Command-line arguments
# ----------------------
parser = argparse.ArgumentParser(
    description='Converts RDA metadata standards directory data into the new'
                ' RDA metadata standards catalog data model, ready for'
                ' importing into a NoSQL database.')
parser.add_argument(
    '-f', '--from',
    help='location of MSD data files',
    action='store',
    default=default_source,
    dest='source')
parser.add_argument(
    '-t', '--to',
    help='location of MSC data files',
    action='store',
    default=default_dest,
    dest='dest')
parser.add_argument(
    '-v', '--vocab',
    help='YAML file containing a mapping from MSD disciplines to MSC subject'
         ' keywords',
    action='store',
    default=kw_mapping,
    dest='map')
args = parser.parse_args()

# Utility variables
# -----------------
#
# Lookup for slug -> new ID
m_index = dict()
g_index = dict()
t_index = dict()

# Collecting information for post-processing
mappings = list()
sponsors = list()
contacts = list()

# Incremental ID integers
n['m'] = 0
n['g'] = 0
n['t'] = 0
n['c'] = 0
e = 0

# Log file contents
if args.dest:
    log_file = os.path.realpath(os.path.join(args.dest, 'migration-log.txt'))
log = ''
isNewLog = False

# Keyword translations
used_keywords = set()
with open(args.map, 'r') as r:
    kw_map = yaml.safe_load(r)


# Utility functions
# -----------------
def get_mscid(path):
    if os.path.isfile(path):
        with open(path, 'r') as r:
            dest_records = yaml.safe_load_all(r)
            dest_record = next(dest_records)
            for identifier in dest_record['identifiers']:
                if identifier['scheme'] == 'RDA-MSCWG':
                    return identifier['id']
    else:
        return None


def load_record(path):
    if os.path.isfile(path):
        with open(path, 'r') as r:
            dest_records = yaml.safe_load_all(r)
            dest_record = next(dest_records)
            return dest_record
    else:
        return None


def translate_keyword(kw):
    used_keywords.add(kw)
    output = None
    if kw in kw_map:
        output = kw_map[kw]
    return output


def create_slug(string):
    # Put to lower case, turn spaces to hyphens
    output = string.strip().lower().replace(' ', '-')
    # Fixes for problem entries
    output = output.replace('é', 'e')
    output = output.replace('access-to', 'access')
    output = output.replace('content-standard-for', 'content-standard')
    output = output.replace('for-interchange-of', 'interchange')
    # Strip out non-alphanumeric ASCII characters
    output = re.sub(r'[^-A-Za-z0-9_]+', '', output)
    # Remove duplicate hyphens
    output = re.sub(r'-+', '-', output)
    # Truncate
    output = output[:71]
    return output

# Processing
# ==========

# Locating data files
# -------------------
print('Scanning {} for data files...'.format(args.source))


def get_records(folder):
    output = list()
    if os.path.isdir(os.path.join(args.source, folder)):
        for entry in os.listdir(os.path.join(args.source, folder)):
            if (entry == 'add.md' or entry == 'index.md'):
                continue
            if (os.path.splitext(entry)[1] != '.md'):
                continue
            output.append(os.path.join(args.source, folder, entry))
        # DEBUG
        print('Subdirectory "{}": found {} records.'.format(
            folder, len(output)))
    else:
        print('Subdirectory "{}" missing, skipping...'.format(folder))
    output.sort()
    return output

standards = get_records('standards')
profiles = get_records('extensions')
tools = get_records('tools')
users = get_records('use_cases')

print('Checking {} for data structure...'.format(args.dest))
n = dict()
for series, folder in {
        'm': 'metadata-schemes',
        'g': 'organizations',
        't': 'tools',
        'c': 'mappings',
        'e': 'endorsements'}.items():
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
                        id_no = int(identifier['id'][5:])
                        if id_no > serial_no:
                            serial_no = id_no
                        break
        n[series] = serial_no
        print('Found {} up to msc:{}{}.'.format(folder, series, serial_no))
    else:
        print('Subdirectory {} missing, creating...'.format(folder))
        os.makedirs(os.path.join(args.dest, folder))

# Parsing data files
# ------------------
#
# Parsing standards
db_standards = dict()
print('Converting standards to MSC data model...')
for record in standards:
    slug = os.path.splitext(os.path.basename(record))[0]
    id_string = get_mscid(
        os.path.join(args.dest, 'metadata-schemes', slug + '.yml'))
    if not id_string:
        n['m'] += 1
        id_string = 'msc:m{}'.format(n['m'])
    m_index[slug] = id_string
    dest_record = dict()

    with open(record, 'r') as r:
        source_records = yaml.safe_load_all(r)
        source_record = next(source_records)
        if 'title' in source_record:
            dest_record['title'] = source_record['title']
        record_id = {'id': id_string, 'scheme': 'RDA-MSCWG'}
        dest_record['identifiers'] = [record_id]
        if 'version' in source_record:
            version = {'number': source_record['version']}
            if 'status' in source_record:
                log += ('Standard {} includes version status {}.\n'
                        ''.format(slug, source_record['status']))
                isNewLog = True
            if 'standard_update_date' in source_record:
                version['issued'] = source_record['standard_update_date']
            dest_record['versions'] = [version]
        if 'description' in source_record:
            rawDescription = source_record['description']
            # Strip out internal links that will not apply in the Catalog
            rawDescription = re.sub(
                r'<a href="(?:..)?/standards[^"]+">([^<]+)</a>', r'\1',
                rawDescription)
            dest_record['description'] = rawDescription
        if 'disciplines' in source_record:
            keywords = list()
            for discipline in source_record['disciplines']:
                kw = translate_keyword(discipline)
                if kw:
                    if isinstance(kw, str):
                        keywords.append(kw)
                    else:
                        keywords += kw
                else:
                    log += ('Found unsupported discipline {} in standard {}.\n'
                            ''.format(discipline, slug))
            if not keywords:
                keywords.append('Multidisciplinary')
            dest_record['keywords'] = keywords
        locations = list()
        if 'specification_url' in source_record:
            location = {
                'url': source_record['specification_url'],
                'type': 'document'}
            locations.append(location)
        if 'website' in source_record:
            location = {
                'url': source_record['website'],
                'type': 'website'}
            locations.append(location)
        if locations:
            dest_record['locations'] = locations
        # The following will be implemented as relations at the end.
        if 'mappings' in source_record:
            for mapping in source_record['mappings']:
                crosswalk = {'from': slug}
                if 'name' in mapping:
                    crosswalk['to'] = mapping['name']
                if 'url' in mapping:
                    crosswalk['url'] = mapping['url']
                mappings.append(crosswalk)
        if 'sponsors' in source_record:
            for sponsor in source_record['sponsors']:
                org = {'standard': slug}
                if 'name' in sponsor:
                    org['name'] = sponsor['name']
                if 'url' in sponsor:
                    org['url'] = sponsor['url']
                sponsors.append(org)
        if 'contact' in source_record:
            org = {'standard': slug, 'name': source_record['contact']}
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
    id_string = get_mscid(
        os.path.join(args.dest, 'metadata-schemes', slug + '.yml'))
    if not id_string:
        n['m'] += 1
        id_string = 'msc:m{}'.format(n['m'])
    m_index[slug] = id_string
    dest_record = dict()

    with open(record, 'r') as r:
        source_records = yaml.safe_load_all(r)
        source_record = next(source_records)
        if 'title' in source_record:
            dest_record['title'] = source_record['title']
        record_id = {'id': id_string, 'scheme': 'RDA-MSCWG'}
        dest_record['identifiers'] = [record_id]
        if 'description' in source_record:
            rawDescription = source_record['description']
            # Strip out internal links that will not apply in the Catalog
            rawDescription = re.sub(
                r'<a href="(?:..)?/standards[^"]+">([^<]+)</a>', r'\1',
                rawDescription)
            dest_record['description'] = rawDescription
        if 'disciplines' in source_record:
            keywords = list()
            for discipline in source_record['disciplines']:
                kw = translate_keyword(discipline)
                if kw:
                    if isinstance(kw, str):
                        keywords.append(kw)
                    else:
                        keywords += kw
                else:
                    log += ('Found unsupported discipline {} in extension {}.'
                            '\n'.format(discipline, slug))
            if not keywords:
                keywords.append('Multidisciplinary')
            dest_record['keywords'] = keywords
        locations = list()
        if 'website' in source_record:
            location = {'url': source_record['website'], 'type': 'website'}
            locations.append(location)
        if locations:
            dest_record['locations'] = locations
        dest_record['relatedEntities'] = list()
        if 'standards' in source_record:
            for standard in source_record['standards']:
                if standard in m_index:
                    parent = {'id': m_index[standard], 'role': 'parent scheme'}
                    dest_record['relatedEntities'].append(parent)
                else:
                    log += ('Extension {} contains reference to unknown parent'
                            ' standard {}.\n'.format(slug, standard))
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
    id_string = get_mscid(os.path.join(args.dest, 'tools', slug + '.yml'))
    if not id_string:
        n['t'] += 1
        id_string = 'msc:t{}'.format(n['t'])
    t_index[slug] = id_string
    dest_record = dict()

    with open(record, 'r') as r:
        source_records = yaml.safe_load_all(r)
        source_record = next(source_records)
        if 'title' in source_record:
            dest_record['title'] = source_record['title']
        record_id = {'id': id_string, 'scheme': 'RDA-MSCWG'}
        dest_record['identifiers'] = [record_id]
        if 'description' in source_record:
            rawDescription = source_record['description']
            # Strip out internal links that will not apply in the Catalog
            rawDescription = re.sub(
                r'<a href="(?:..)?/standards[^"]+">([^<]+)</a>', r'\1',
                rawDescription)
            dest_record['description'] = rawDescription
        locations = list()
        if 'website' in source_record:
            location = {'url': source_record['website'], 'type': 'website'}
            locations.append(location)
        if locations:
            dest_record['locations'] = locations
        dest_record['relatedEntities'] = list()
        if 'standards' in source_record:
            for standard in source_record['standards']:
                if standard in m_index:
                    supported = {
                        'id': m_index[standard],
                        'role': 'supported scheme'}
                    dest_record['relatedEntities'].append(supported)
                else:
                    log += ('Tool {} contains reference to unknown standard'
                            ' {}.\n'.format(slug, standard))
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
    id_string = get_mscid(os.path.join(args.dest, 'organizations', slug + '.yml'))
    if not id_string:
        n['g'] += 1
        id_string = 'msc:g{}'.format(n['g'])
    g_index[slug] = id_string
    dest_record = dict()

    with open(record, 'r') as r:
        source_records = yaml.safe_load_all(r)
        source_record = next(source_records)
        if 'title' in source_record:
            dest_record['name'] = source_record['title']
        record_id = {'id': id_string, 'scheme': 'RDA-MSCWG'}
        dest_record['identifiers'] = [record_id]
        if 'description' in source_record:
            rawDescription = source_record['description']
            # Strip out internal links that will not apply in the Catalog
            rawDescription = re.sub(
                r'<a href="(?:..)?/standards[^"]+">([^<]+)</a>', r'\1',
                rawDescription)
            dest_record['description'] = rawDescription
        locations = list()
        if 'website' in source_record:
            location = {'url': source_record['website'], 'type': 'website'}
            locations.append(location)
        if locations:
            dest_record['locations'] = locations
        if 'standards' in source_record:
            for standard in source_record['standards']:
                if standard in m_index:
                    # Insert relation in other record
                    relation = {'id': id_string, 'role': 'user'}
                    if 'relatedEntities' not in db_standards[standard]:
                        db_standards[standard]['relatedEntities'] = list()
                    db_standards[standard]['relatedEntities'].append(relation)
                else:
                    log += ('Use case {} contains reference to unknown'
                            ' standard {}.\n'.format(slug, standard))
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
    slug_to = create_slug(mapping['to'])
    slug += '-'.join(slug_to.split('-')[:3])
    id_string = get_mscid(os.path.join(args.dest, 'mappings', slug + '.yml'))
    if not id_string:
        n['c'] += 1
        id_string = 'msc:c{}'.format(n['c'])
    dest_record = dict()

    record_id = {'id': id_string, 'scheme': 'RDA-MSCWG'}
    dest_record['identifiers'] = [record_id]
    if 'url' in mapping:
        location = {'url': mapping['url'], 'type': 'document'}
        dest_record['locations'] = [location]
    related = list()
    description = 'A mapping from '
    if 'from' in mapping:
        relation = dict()
        if slug_from in m_index:
            relation['id'] = m_index[slug_from]
            description += db_standards[slug_from]['title']
        else:
            log += ('Mapping encountered from unknown standard {}. There is a'
                    ' bug in the migration script.\n'.format(slug_from))
            isNewLog = True
            description += slug_from
        relation['role'] = 'input scheme'
        related.append(relation)
    if 'to' in mapping:
        relation = dict()
        name = mapping['to']
        description += ' to {}.'.format(name)
        if slug_to in m_index:
            relation['id'] = m_index[slug_to]
        else:
            to_id_string = get_mscid(
                os.path.join(args.dest, 'metadata-schemes', slug_to + '.yml'))
            if to_id_string:
                log += ('In standard {}, found mapping to unknown standard {};'
                        ' reusing stub from previous run.\n'
                        ''.format(slug_from, slug_to))
                isNewLog = True
                relation['id'] = to_id_string
                m_index[slug_to] = to_id_string
                db_standards[slug_to] = load_record(
                    os.path.join(
                        args.dest, 'metadata-schemes', slug_to + '.yml'))
            else:
                # Unknown scheme: create stub
                log += ('In standard {}, found mapping to unknown standard {}'
                        ' so created a stub.\n'.format(slug_from, slug_to))
                isNewLog = True
                n['m'] += 1
                standard_id_string = 'msc:m{}'.format(n['m'])
                m_index[slug_to] = standard_id_string
                standard_record = dict()
                standard_record_id = {
                    'id': standard_id_string,
                    'scheme': 'RDA-MSCWG'}
                standard_record['identifiers'] = [standard_record_id]
                standard_record['title'] = name
                db_standards[slug_to] = standard_record
                relation['id'] = standard_id_string
        relation['role'] = 'output scheme'
        related.append(relation)
    dest_record['relatedEntities'] = related
    dest_record['description'] = description

    db_mappings[slug] = dest_record

if isNewLog:
    log += '\n'
    isNewLog = False

# Creating sponsor records
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
        # See if an organization with this name already exists in the database
        slug = create_slug(sponsor['name'])
        if slug in g_index:
            id_string = g_index[slug]
        else:
            # See if an organization with this name already exists from a
            # previous migration run
            id_string = get_mscid(
                os.path.join(args.dest, 'organizations', slug + '.yml'))
            if id_string:
                g_index[slug] = id_string
                db_organizations[slug] = load_record(
                    os.path.join(args.dest, 'organizations', slug + '.yml'))
                log += ('In standard {}, found reference to unknown sponsor'
                        ' {}; reusing stub from previous run.\n'
                        ''.format(standard, slug))
                isNewLog = True
    else:
        # See if an organization with this URL already exists in the database
        if 'url' in sponsor:
            for org_slug, org in db_organizations:
                if 'locations' in org:
                    for location in org['locations']:
                        if 'url' in location:
                            if sponsor['url'] == location['url']:
                                slug = org_slug
                                id_string = g_index[slug]
                                break
                                break
    if (not id_string) and slug:
        # Need to create new record
        log += ('In standard {}, found reference to unknown sponsor {} so'
                ' created a stub.\n'.format(standard, slug))
        isNewLog = True
        n['g'] += 1
        id_string = 'msc:g{}'.format(n['g'])
        g_index[slug] = id_string
        dest_record = dict()
        dest_record['name'] = sponsor['name']
        record_id = {'id': id_string, 'scheme': 'RDA-MSCWG'}
        dest_record['identifiers'] = [record_id]
        locations = list()
        if 'url' in sponsor:
            location = {'url': sponsor['url'], 'type': 'website'}
            locations.append(location)
            dest_record['locations'] = locations
        db_organizations[slug] = dest_record
    if id_string:
        # We can add a cross-reference now
        relation = {'id': id_string, 'role': 'maintainer'}
        if 'relatedEntities' not in db_standards[standard]:
            db_standards[standard]['relatedEntities'] = list()
        db_standards[standard]['relatedEntities'].append(relation)
    else:
        print('WARNING: incomplete sponsor information in {}.'
              ''.format(standard))

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
        # See if an organization with this name already exists in the database
        slug = create_slug(contact['name'])
        if slug in g_index:
            id_string = g_index[slug]
        else:
            # See if an organization with this name already exists from a
            # previous migration run
            id_string = get_mscid(
                os.path.join(args.dest, 'organizations', slug + '.yml'))
            if id_string:
                g_index[slug] = id_string
                db_organizations[slug] = load_record(
                    os.path.join(args.dest, 'organizations', slug + '.yml'))
                log += ('In standard {}, found reference to unknown contact'
                        ' {}; reusing stub from previous run.\n'
                        ''.format(standard, slug))
                isNewLog = True
    else:
        if 'email' in contact:
            # See if an organization with this email address already exists in
            # the database
            for org_slug, org in db_organizations:
                if 'locations' in org:
                    for location in org['locations']:
                        if 'url' in location:
                            if contact['email'] == location['url']:
                                slug = org_slug
                                id_string = g_index[slug]
                                break
                                break
    if (not id_string) and slug:
        # Need to create new record
        log += ('In standard {}, found reference to unknown contact {} so'
                ' created a stub.\n'.format(standard, slug))
        isNewLog = True
        n['g'] += 1
        id_string = 'msc:g{}'.format(n['g'])
        g_index[slug] = id_string
        dest_record = dict()
        dest_record['name'] = contact['name']
        record_id = {'id': id_string, 'scheme': 'RDA-MSCWG'}
        dest_record['identifiers'] = [record_id]
        locations = list()
        if 'email' in contact:
            location = {'url': contact['email'], 'type': 'email'}
            locations.append(location)
            dest_record['locations'] = locations
        db_organizations[slug] = dest_record
    if id_string and slug:
        # We can add a cross-reference now
        relation = {'id': id_string, 'role': 'maintainer'}
        if 'relatedEntities' not in db_standards[standard]:
            db_standards[standard]['relatedEntities'] = list()
        # ... but only if it is not already there (from sponsors)
        isNew = True
        for known_relation in db_standards[standard]['relatedEntities']:
            if known_relation == relation:
                isNew = False
                break
        if isNew:
            db_standards[standard]['relatedEntities'].append(relation)
        # Add email address to org record if missing
        if 'email' in contact:
            isEmailMissing = True
            if 'locations' in db_organizations[slug]:
                for location in db_organizations[slug]['locations']:
                    if 'type' in location and location['type'] == 'email':
                        isEmailMissing = False
                        break
            else:
                db_organizations[slug]['locations'] = list()
            if isEmailMissing:
                location = {'url': contact['email'], 'type': 'email'}
                db_organizations[slug]['locations'].append(location)
    else:
        log += ('Standard {} has incomplete contact information.'
                ''.format(standard))
        isNewLog = True

if isNewLog:
    log += '\n'
    isNewLog = False

# Writing migrated data to files
# ------------------------------
print('Writing out new records...')
for slug, dest_record in db_standards.items():
    new_record = os.path.join(args.dest, 'metadata-schemes', slug + '.yml')
    with open(new_record, 'w') as r:
        yaml.safe_dump(
            dest_record, r, default_flow_style=False, allow_unicode=True)
for slug, dest_record in db_tools.items():
    new_record = os.path.join(args.dest, 'tools', slug + '.yml')
    with open(new_record, 'w') as r:
        yaml.safe_dump(
            dest_record, r, default_flow_style=False, allow_unicode=True)
for slug, dest_record in db_organizations.items():
    new_record = os.path.join(args.dest, 'organizations', slug + '.yml')
    with open(new_record, 'w') as r:
        yaml.safe_dump(
            dest_record, r, default_flow_style=False, allow_unicode=True)
for slug, dest_record in db_mappings.items():
    new_record = os.path.join(args.dest, 'mappings', slug + '.yml')
    with open(new_record, 'w') as r:
        yaml.safe_dump(
            dest_record, r, default_flow_style=False, allow_unicode=True)

print('There were issues you should look at: see migration log.')
log = ('Migration log: {}\n\n'
       ''.format(datetime.datetime.now(datetime.timezone.utc).isoformat(' ')) +
       log)
if log:
    with open(log_file, 'w') as l:
        l.write(log)

if used_keywords:
    with open(kw_file, 'w') as k:
        kw_list = list(used_keywords)
        kw_list.sort()
        for kw in kw_list:
            k.write(kw + '\n')

print('Finished!')
