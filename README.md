# Metadata Standards Catalog Development

This repository is for experimental code used in the development of the
Metadata Standards Catalog.

## Migrating data from the Metadata Standards Directory

The easiest way to proceed is to set up local copies of this repository and
that of the Metadata Standards Directory within neighbouring folders:

```bash
git clone https://github.com/rd-alliance/metadata-catalog-dev.git
git clone https://github.com/rd-alliance/metadata-directory.git
```

That is, you should end up with something like this:

```
rda-dev/
    metadata-catalog-dev/
    metadata-directory/
```

To proceed you will need an installation of [Python 3] and the non-standard
library [PyYAML]. (Ubuntu/Debian users: this means the `python3` and
`python3-yaml` packages.)

[Python 3]: https://www.python.org/
[PyYAML]: http://pyyaml.org/wiki/PyYAML

Within this folder, run the Python script `migrate.py`. On UNIX systems, you
should be able to use it directly (add the `-h` flag to see the available
options):

```bash
./migrate.py
```

Otherwise you may need to get Python to run it explicitly:

```bash
python migrate.py
```

This should produce the following files and folders:

  - `db/`: contains a further 5 folders in which the migrated data are
    stored in `.yml` files. (The endorsements folder will be empty)
  - `disciplines.yml`: a report of all the disciplines uses in the Metadata
    Standards Directory, useful if you want to write your own mapping to a
    different controlled vocabulary.
  - `migration-log.yml`: a report of things that might need to be tidied up
    manually, e.g. unrecognized disciplines or sponsor organizations.

Note that the `db/` folder is now part of the version-controlled code.

## Compiling the data into a NoSQL database

Once you are happy with the data in its human-friendly YAML format, you will
need to compile it to a single app-friendly JSON file. For this you can use the
[Python 3] script `dbctl.py`. You will again need [PyYAML] but you will also
need some other non-standard libraries:

- For reading/writing to the databases, you will need [TinyDB] and [RDFLib].
- For version control of the databases, you will need [Dulwich].
- For password hashing (see below), you will need [PassLib].

(Ubuntu/Debian users: TinyDB has not been packaged for Ubuntu so you will
probably want to install it with `python3-pip`. RDFLib has been packaged as
`python3-rdflib`, Dulwich as `python3-dulwich`, PassLib as `python3-passlib`.)

[TinyDB]: http://tinydb.readthedocs.io/
[RDFLib]: http://rdflib.readthedocs.io/
[Dulwich]: https://www.dulwich.io/
[PassLib]: https://passlib.readthedocs.io/

If you are using the defaults you should be able to generate a file `db.json`
(in an `instance/data` folder) by running the script with the `compile`
action:

```bash
./dbctl.py compile
```

If at any point you want to turn the database back into individual YAML files,
you can do this with the `dump` action:

```bash
./dbctl.py dump
```

If this would overwrite your original set of YAML files, you have the choice of
deleting them, backing them up (to `db0`, `db1`, `db2`, etc.), or cancelling.

## Generating the subject ontology

The `dbctl.py` script can also be used to generate the RDF subject thesaurus
used by the Catalog.

```.bash
./dbctl.py vocab
```

This will take either the local file `unesco-thesaurus.ttl` or the live version
of the UNESCO Vocabulary on the Web and transform it into
`simple-unesco-thesaurus.ttl`. The transformation consists of stripping out
unused triples and (in a somewhat hackish manner) enabling the domains and
microthesauri to be traversed as if they were higher level concepts.

## Managing users

You can use `dbctl.py` to perform actions on the user database not available through the Metadata Standards Catalog interfaces. This separation is a security measure.

To add a new API user, run the script with `add-api-user` action and three arguments:

```.bash
./dbctl.py add-api-user "Readable name" "user ID" "email address"
```

  - The readable name can be anything, but Git will not be happy if it is too
    long. It is only used in the Git logs.
  - The user ID (username) can only contain ASCII letters (upper or lower case),
    digits, hyphens or underscores.
  - Some light verification is performed on the email address as well. It is
    only used in the Git logs.

The script will return an automatically generated password. This (and the user
ID, if not chosen by them) should be passed to the API user; they should be
encouraged to change the password as soon as possible, but this is not enforced.

To block or unblock a user, use one of the following actions:

```.bash
./dbctl.py block-user "user ID"
./dbctl.py block-api-user "user ID"
./dbctl.py unblock-user "user ID"
./dbctl.py unblock-api-user "user ID"
```

The user ID must correspond to a `userid` value in the database.

## Running the prototype Metadata Standards Catalog

To run the prototype Catalog, you will need quite a lot of non-standard packages, but all of them are easily available via the `pip` utility:

  - For the actual rendering of the pages you will need [Flask], [Flask-WTF]
    (and hence [WTForms]), and [Flask-Login].
  - For Open ID v2.x login support, you will need [Flask-OpenID].
  - For Open ID Connect (OAuth) support, you will need [RAuth] (and hence
    [Requests]), and Google's [oauth2client].
  - For API authentication, you will need [Flask-HTTPAuth] and [PassLib]
  - For database capability, you will need [TinyDB], [tinyrecord], and [RDFLib].
  - For version control of the databases, you will need [Dulwich].

[Flask]: http://flask.pocoo.org/
[Flask-WTF]: https://flask-wtf.readthedocs.io/
[WTForms]: https://wtforms.readthedocs.io/
[Flask-Login]: https://flask-login.readthedocs.io/
[Flask-OpenID]: https://pythonhosted.org/Flask-OpenID/
[RAuth]: https://rauth.readthedocs.io/
[Requests]: http://docs.python-requests.org/
[oauth2client]: https://developers.google.com/api-client-library/python/guide/aaa_oauth
[Flask-HTTPAuth]: https://flask-httpauth.readthedocs.io/
[tinyrecord]: https://github.com/eugene-eeo/tinyrecord

The Catalog is compatible with Flask 0.10 (this is what `python3-flask` gives
you in Ubuntu LTS releases).

For best results, you should already have generated your database using the
above `dbctl.py` script. By default Flask will look for it in the `instance`
folder (as `data/db.json`); it will be created for you if it doesn't exist.
You can change the locations of the database files by putting the paths in a
configuration file, e.g. `settings.cfg`:

```python
MAIN_DATABASE_PATH = os.path.join('path', 'to', 'file.json')
USER_DATABASE_PATH = os.path.join('path', 'to', 'file.json')
OAUTH_DATABASE_PATH = os.path.join('path', 'to', 'file.json')
OPENID_PATH = os.path.join('path', 'to', 'folder')
```

These four are, respectively,

 1. The database that holds the records for schemes, tools, mappings, etc.
 2. The database that holds the user profiles.
 3. The database that holds OAuth URLs discovered dynamically.
 4. A temporary folder used by the Open ID v2 library.

To ensure Flask sees your configuration file, set an environment variable that
contains the full path to the file. On UNIX-like systems:

```bash
export MSC_SETTINGS=/path/to/settings.cfg
```

...and on Windows:

```batchfile
set MSC_SETTINGS=\path\to\settings.cfg
```

Open up a fresh terminal/command prompt (as it will block the command line for
as long as the script is running) and run the [Python 3] script `serve.py`:

```bash
./serve.py
```

You should then be able to access the Catalog in your Web browser using the URL
the script shows you, e.g. <http://127.0.0.1:5000/>.

## Testing the public API

### Display record

To test retrieval of a record in JSON, use something like the following:

```bash
curl -H 'Accept: application/json' http://127.0.0.1:5000/msc/m13
```

The convention for dereferencing the MSC internal IDs is to replace the initial
`msc:` with the URL of the Catalog followed by `/msc/`.

### Search for records

To test the retrieval of internal IDs in response to a query, use something
like the following:

```bash
curl -X POST -F 'title=ABCD' -H 'Accept: application/json' http://127.0.0.1:5000/query/schemes
```

Supported queries when retrieving a list of scheme IDs:

  * `title`: searches within the title using regular expression syntax.

  * `keyword`: searches for an exact match within the list of keywords.

  * `keyword_id`: accepts a URI from the UNESCO Vocabulary, which is translated
    into a keyword and used as for `keyword` above.

  * `identifier`: searches for an exact match within the list of identifiers.
    The primary use of this is to search for schemes by external identifier,
    though it can also be used to test if an internal ID is in use.

  * `funder`: searches, using regular expression syntax, within the names of
    organizations listed as funders of the scheme.

  * `funder_id`: searches for an exact match within the list of identifiers of
    organizations listed as funders of the scheme.

  * `dataType`: searches for an exact match within the list of data types.

The response will be a JSON object, consisting of the key `ids` with an array
as its value:

```json
{ "ids": [ "msc:m1", "msc:m2" ] }
```

## Testing the restricted API

In order to use the restricted API, you will need to have your organization or
application registered in the user database. Application accounts must have a
name, email address and password.

These accounts must be set up by an administrator, and cannot be added through
the Web interface.

### Change password

To change the password, use something like the following:

```bash
curl -u userid:password -X POST -H "Content-Type: application/json" -d '{"new_password": "your_new_password"}' http://127.0.0.1:5000/api/reset-password
```

If successful , the response will be a JSON object like this:

```json
{ "username": "your_username", "password_reset": "true"}
```

### Get token

To receive an authorization token, use something like the following:

```bash
curl -u userid:password -X GET http://127.0.0.1:5000/api/token
```

If authentication is successful, the response will be a JSON object, consisting
of the key `token` and a long string as the value:

```json
{ "token": "the_actual_token_itself" }
```

The token will be valid for 600 seconds.

### Create a new record

To create a new record, send a POST request to one of the following URLs:

  - `http://127.0.0.1:5000/api/m` for a metadata scheme
  - `http://127.0.0.1:5000/api/g` for an organization
  - `http://127.0.0.1:5000/api/t` for a tool
  - `http://127.0.0.1:5000/api/c` for a mapping
  - `http://127.0.0.1:5000/api/e` for an endorsement

The body of the request should be a JSON object representing the complete record. Example:

```bash
curl -u token:anything -X POST -H 'Content-Type: application/json' -d '{"name": "Test group", "description": "This is a test.", "types": [ "coordination group" ] }' http://127.0.0.1:5000/api/g
```

The response will be a JSON object, consisting of three keys:

  - `success` indicates whether the record was created successfully;
  - `conformance` indicates if the record was judged to be invalid, valid,
    useful, or complete;
  - if the record was invalid, `errors` contains the reasons why the record was
    rejected, otherwise `id` contains the MSC ID of the new record.

```json
{ "success": true, "conformance": "valid", "id": "msc:g99" }
```

```json
{ "success": false, "conformance": "invalid", "errors": { "locations": [ { "type": [ "This field is required." ] } ] } }
```
