import yaml
import re
import os
import json

yamldir='../db/metadata-schemes'
files = os.listdir(yamldir)

#yamlfile='../db/metadata-schemes/abcd-access-biological-collection-data.yml'
yamlfile='../db/metadata-schemes/datacite-metadata-schema.yml'
standards = dict()
for yamlfile in files:
    print(yamlfile)
    with open(yamldir+'/'+yamlfile, 'r') as stream:
        yamlstr = stream.read()
        try:
            id=None
            data = yaml.safe_load(yamlstr)
            identifiers = data.get('identifiers')
            for identifier in identifiers:
                if identifier.get('scheme') == 'RDA-MSCWG':
                    id = identifier.get('id')
            subjects= data.get('keywords')
            title = data.get('title')
            urlmatch = re.findall(r"url:\s?(.*)$", yamlstr, re.MULTILINE)
            for uri in urlmatch:
                standards[uri] = {'title': title,'identifier': id, 'subject_areas':subjects}
            #standards[title] = {'identifier': id, 'urls': urlmatch, 'subject_areas':subjects}

        except yaml.YAMLError as exc:
            print('ERROR: '+yamlfile)
print(json.dumps(standards))