# Metadata Standards Catalog Development

This repository contains the code base for the Research Data Alliance [Metadata
Standards Catalog].

For information on how to install and run an instance of the Catalog yourself,
see the [Installation Guide].

For information on how to administer a running instance of the Catalog, see the
[Administrator's Guide].

[Metadata Standards Catalog]: https://rdamsc.dcc.ac.uk/
[Installation Guide]: INSTALLATION.md
[Administrator's Guide]: ADMINISTRATION.md

## Using the public API

### Display one record

To retrieve a record in JSON, send a GET request to a URL formed from the
internal MSC ID: replace the initial `msc:` with the URL of the Catalog followed
by either

  - `/msc/`, in which case you have to specify JSON format in the headers, e.g.

    ```bash
    curl -H 'Accept: application/json' https://rdamsc.dcc.ac.uk/msc/m13
    ```

  - `/api/`, in which case you get JSON automatically, e.g.

    ```bash
    curl https://rdamsc.dcc.ac.uk/api/m13
    ```

The response you will get will be a JSON object that is structurally similar to
the YAML files in the `db` directory in this repository; see the [database
documentation][dbguide] for details. Unlike the HTML equivalent, it will not
pull in information from other records in the database, so to get the full
picture you will need to make multiple requests.

Please indicate in the [issue tracker][issues] if you would like to us to
provide a method for retrieving a composite record in one go.

[dbguide]: /db/README.md
[issues]: https://github.com/rd-alliance/metadata-catalog-dev/issues

### Search for records

To perform a search of the database, and receive a list of internal MSC IDs in
return, use something like the following:

```bash
curl -X POST -F 'title=ABCD' https://rdamsc.dcc.ac.uk/query/schemes
curl -X POST -F 'name=University' https://rdamsc.dcc.ac.uk/query/organizations
curl -X POST -F 'supported_scheme=msc:m13' https://rdamsc.dcc.ac.uk/query/tools
curl -X POST -F 'input_scheme=msc:m15' -F 'output_scheme=msc:m11' https://rdamsc.dcc.ac.uk/query/mappings
curl -X POST -F 'endorsed_scheme=msc:m46'  https://rdamsc.dcc.ac.uk/query/endorsements
```

Unless otherwise stated, if you search using more than one field, the result set
will be broadened. In other words, it will be as if you searched using each
field individually then combined the results.

Supported queries when retrieving a list of scheme IDs:

  * `title`: searches within the title using regular expression syntax.

  * `keyword`: searches for an exact match for the given term, plus narrower and
    broader terms, within the list of keywords. To search for more than one
    keyword at once, separate the keywords with pipes,
    e.g. `keyword=Astronomy|Biology`.

  * `keyword_id`: works similarly to `keyword`, but accepts one or more URIs
    from the UNESCO Vocabulary, separated by pipes. (You may notice a difference
    in behaviour from `keyword` since it skips an initial translation step.)

  * `identifier`: searches for an exact match within the list of identifiers.
    The primary use of this is to search for schemes by external identifier,
    though it can also be used to test if an internal ID is in use.

  * `funder`: searches, using Python's regular expression syntax, within the
    names of organizations listed as funders of the scheme.

  * `funder_id`: searches for an exact match within the list of identifiers of
    organizations listed as funders of the scheme.

  * `dataType`: searches for an exact match within the list of data types.

Supported queries when retrieving a list of organization IDs:

  * `name`: searches within the name using regular expression syntax.

  * `identifier`: searches for an exact match within the list of identifiers.
    The primary use of this is to search for schemes by external identifier,
    though it can also be used to test if an internal ID is in use.

  * `type`: searches for organizations of the given type, drawn from the
    controlled vocabulary.

Supported queries when retrieving a list of tool IDs:

  * `title`: searches within the title using regular expression syntax.

  * `identifier`: searches for an exact match within the list of identifiers.
    The primary use of this is to search for schemes by external identifier,
    though it can also be used to test if an internal ID is in use.

  * `type`: searches for tools of the given type, drawn from the controlled
    vocabulary.

  * `supported_scheme`: searches for tools that support the given scheme,
    expressed as an internal identifier.

Supported queries when retrieving a list of mapping IDs:

  * `identifier`: searches for an exact match within the list of identifiers.
    The primary use of this is to search for schemes by external identifier,
    though it can also be used to test if an internal ID is in use.

  * `input_scheme`: searches for mappings from the given scheme, expressed as
    an internal identifier. Contrary to how other fields work, the search will
    be narrowed if you also give an `output_scheme`.

  * `output_scheme`: searches for mappings to the given scheme, expressed as
    an internal identifier. Contrary to how other fields work, the search will
    be narrowed if you also give an `input_scheme`.

Supported queries when retrieving a list of endorsement IDs:

  * `identifier`: searches for an exact match within the list of identifiers.
    The primary use of this is to search for schemes by external identifier,
    though it can also be used to test if an internal ID is in use.

  * `endorsed_scheme`: searches for endorsements of the given scheme,
    expressed as an internal identifier.

The response will be a JSON object, consisting of the key `ids` with an array
as its value:

```json
{ "ids": [ "msc:m1", "msc:m2" ] }
```

### List records

To get a list of all the records of a particular type, send a GET request to one
of the following URLs:

  - `https://rdamsc.dcc.ac.uk/api/m` for metadata schemes
  - `https://rdamsc.dcc.ac.uk/api/g` for organizations
  - `https://rdamsc.dcc.ac.uk/api/t` for tools
  - `https://rdamsc.dcc.ac.uk/api/c` for mappings
  - `https://rdamsc.dcc.ac.uk/api/e` for endorsements

The response will be a JSON object, consisting of a key representing the type of
record (e.g. `metadata-schemes`) with an array of objects as its value. Each
object has two keys:

  - `id`: the MSC ID of the record
  - `slug`: a less opaque identifying string for the record, derived from the
    title of a metadata scheme, the name of an organization, etc. This is the
    same string used to generate file names when dumping the database to
    individual YAML files.

## Using the restricted API

In order to use the restricted API, you will need to have your organization or
application registered in the user database. Application accounts must have a
name, email address and password.

These accounts must be set up by an administrator, and cannot be added through
the Web interface.

WARNING: It is not recommended to use the restricted API of the live system yet.
Please wait until an SSL certificate has been set up so you can use HTTPS,
otherwise your username and password may be at risk of interception.

### Change password

To change the password, use something like the following:

```bash
curl -u userid:password -X POST -H "Content-Type: application/json" -d '{"new_password": "your_new_password"}' https://rdamsc.dcc.ac.uk/api/reset-password
```

If successful , the response will be a JSON object like this:

```json
{ "username": "your_username", "password_reset": "true"}
```

### Get token

To receive an authorization token, use something like the following:

```bash
curl -u userid:password -X GET https://rdamsc.dcc.ac.uk/api/token
```

If authentication is successful, the response will be a JSON object, consisting
of the key `token` and a long string as the value:

```json
{ "token": "the_actual_token_itself" }
```

The token will be valid for 600 seconds.

### Create a new record

To create a new record, send a POST request to one of the following URLs:

  - `https://rdamsc.dcc.ac.uk/api/m` for a metadata scheme
  - `https://rdamsc.dcc.ac.uk/api/g` for an organization
  - `https://rdamsc.dcc.ac.uk/api/t` for a tool
  - `https://rdamsc.dcc.ac.uk/api/c` for a mapping
  - `https://rdamsc.dcc.ac.uk/api/e` for an endorsement

The body of the request should be a JSON object representing the complete
record; see the [database documentation][dbguide] for details. Example:

```bash
curl -u token:anything -X POST -H 'Content-Type: application/json' -d '{"name": "Test group", "description": "This is a test.", "types": [ "coordination group" ] }' https://rdamsc.dcc.ac.uk/api/g
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

### Modify an existing record

To modify a record, send a PUT request to `https://rdamsc.dcc.ac.uk/api/` followed
by the MSC ID, e.g. `https://rdamsc.dcc.ac.uk/api/m1`.

The body of the request should be a JSON object representing the complete
record; see the [database documentation][dbguide] for details. Example:

```bash
curl -u token:anything -X PUT -H 'Content-Type: application/json' -d '{"name": "Test group", "description": "This is a test.", "types": [ "coordination group" ] }' https://rdamsc.dcc.ac.uk/api/g99
```

The response is the same as for ‘Create a new record’.

### Delete an existing record

To delete a record, send a DELETE request to `https://rdamsc.dcc.ac.uk/api/`
followed by the MSC ID, e.g. `https://rdamsc.dcc.ac.uk/api/m1`. Example:

```bash
curl -u token:anything -X DELETE https://rdamsc.dcc.ac.uk/api/g99
```

The response will be a JSON object, consisting of three keys:

  - `success` indicates whether the record was deleted successfully;
  - `id`, containing the MSC ID of the deleted record.

```json
{ "success": true, "id": "msc:g99" }
```
