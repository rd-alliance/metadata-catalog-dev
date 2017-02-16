# Metadata Standards Catalog Development

This repository is for experimental code used in the development of the
Metadata Standards Catalog. Nothing here is ready for the prime time yet!

## Migrating data from the Metadata Standards Directory

The easiest way to proceed is to set up local copies of this repository and
that of the Metadata Standards Directory within neighbouring folders:

~~~{.bash}
git clone https://github.com/rd-alliance/metadata-catalog-dev.git
git clone https://github.com/rd-alliance/metadata-directory.git
~~~

That is, you should end up with something like this:

~~~
/ rda-dev
    / metadata-catalog-dev
    / metadata-directory
~~~

To proceed you will need an installation of [Python 3] and the non-standard
library [PyYAML]. (On Ubuntu and similar, this means the `python3` and
`python3-yaml` packages.)

[Python 3]: https://www.python.org/
[PyYAML]: http://pyyaml.org/wiki/PyYAML

Within this folder, run the Python script `migrate.py`. On UNIX systems, you
should be able to use it directly (add the `-h` flag to see the available
options):

~~~{.bash}
./migrate.py
~~~

Otherwise you may need to get Python to run it explicitly:

~~~{.bash}
python migrate.py
~~~

This should produce the following files and folders:

  - `db/`: contains a further 5 folders in which the migrated data are
    stored in `.yml` files.
  - `disciplines.yml`: a report of all the disciplines uses in the Metadata
    Standards Directory, useful if you want to write your own mapping to a
    different controlled vocabulary.
  - `migration-log.yml`: a report of things that might need to be tidied up
    manually, e.g. unrecognized disciplines or sponsor organizations.

## Compiling the data into a NoSQL database

Once you are happy with the data in its human-friendly YAML format, you will
need to compile it to a single app-friendly JSON file. For this you can use the
[Python 3] script `dbctl.py`. You will again need [PyYAML] but you will also
need the non-standard libraries [TinyDB] and [RDFLib]. (TinyDB has not been
packaged for Ubuntu so you will probably want to install it with `python3-pip`.
RDFLib has been packaged as `python3-rdflib`.)

[TinyDB]: http://tinydb.readthedocs.io/
[RDFLib]: http://rdflib.readthedocs.io/

If you are using the defaults you should be able to generate a file `db.json` by
running the script with the `compile` action:

~~~{.bash}
./dbctl.py compile
~~~

If at any point you want to turn the database back into individual YAML files,
you can do this with the `dump` action:

~~~{.bash}
./dbctl.py dump
~~~

If this would overwrite your original set of YAML files, you have the choice of
deleting them, backing them up (to `db0`, `db1`, `db2`, etc.), or cancelling.

## Generating the subject ontology

The `dbctl.py` script can also be used to generate the RDF subject thesaurus
used by the Catalog.

~~~{.bash}
./dbctl.py vocab
~~~

This will take either the local file `unesco-thesaurus.ttl` or the live version
of the UNESCO Vocabulary on the Web and transform it into
`simple-unesco-thesaurus.ttl`. The transformation consists of stripping out
unused triples and (in a somewhat hackish manner) enabling the domains and
microthesauri to be traversed as if they were higher level concepts.

## Running the prototype Metadata Standards Catalog

To run the prototype Catalog, you will need [TinyDB], [RDFLib] and [Flask]. It
is currently compatible with Flask 0.10 (this is what `python3-flask` gives you
in Ubuntu LTS releases).

[Flask]: http://flask.pocoo.org/

Open up a fresh terminal/command prompt (as it will block the command line for
as long as the script is running) and run the [Python 3] script `serve.py`:

~~~{.bash}
./serve.py
~~~

You should then be able to access the Catalog in your Web browser using the URL
the script shows you, e.g. <http://127.0.0.1:5000/>.

## Testing the API

To test retrieval of a record in JSON, use something like the following:

~~~{.bash}
curl -H 'Accept: application/json' http://127.0.0.1:5000/msc/m13
~~~

The convention for dereferencing the MSC internal IDs is to replace the initial
`msc:` with the URL of the Catalog followed by `/msc/`.

To test the retrieval of internal IDs in response to a query, use something
like the following:

~~~{.bash}
curl -X POST -F 'title=ABCD' -H 'Accept: application/json' http://127.0.0.1:5000/query/schemes
~~~

Supported queries when retrieving a list of scheme IDs:

  * `title`: searches within the title using regular expression syntax.

  * `keyword`: searches for an exact match within the list of keywords.

  * `keyword-id`: accepts a URI from the UNESCO Vocabulary, which is translated
    into a keyword and used as for `keyword` above.

  * `id`: searches for an exact match within the list of identifiers.
    The primary use of this is to search for schemes by external identifier,
    though it can also be used to test if an internal ID is in use.

  * `funder`: searches, using regular expression syntax, within the names of
    organizations listed as funders of the scheme.

  * `funder-id`: searches for an exact match within the list of identifiers of
    organizations listed as funders of the scheme.

  * `dataType`: searches for an exact match within the list of data types.

The response will be a JSON object, consisting of the key `ids` with an array
as its value:

~~~{.json}
{ "ids": [ "msc:m1", "msc:m2" ] }
~~~
