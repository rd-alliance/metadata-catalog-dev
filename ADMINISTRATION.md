# Administering the Metadata Standards Catalog

## Introduction

Most of the administrative functions you need for managing the Metadata Standards Catalog are implemented in the database control script `dbctl.py`.

The script is written in [Python 3], so as a first step this will need to be
installed on your machine. You will also need quite a few non-standard packages,
but all of them are easily available via the `pip` utility:

  - For reading YAML files, you will need [PyYAML].
  - For reading/writing to the databases, you will need [TinyDB] v.3.6.0+ and
    [RDFLib].
  - For version control of the databases, you will need [Dulwich].
  - For password hashing, you will need [PassLib].

[Python 3]: https://www.python.org/
[PyYAML]: http://pyyaml.org/wiki/PyYAML
[TinyDB]: http://tinydb.readthedocs.io/
[RDFLib]: http://rdflib.readthedocs.io/
[Dulwich]: https://www.dulwich.io/
[PassLib]: https://passlib.readthedocs.io/

(Ubuntu/Debian users: TinyDB has not been packaged for Ubuntu so you will
probably want to install it with `python3-pip`. PyYAML has been packaged as
`python3-yaml`, RDFLib `python3-rdflib`, Dulwich as `python3-dulwich`, PassLib
as `python3-passlib`.)

Depending on your operating system you might be able to run the script directly:

```bash
./dbctl.py --help
```

Otherwise you might need to invoke `python` or `python3`:

```bash
python3 dbctl.py --help
```

There are sections below on particular tasks:

  - [Managing users](#managing-users)
  - [Backing up and restoring the database](#backing-up-and-restoring-the-database)
  - [Updating the subject ontology](#updating-the-subject-ontology)
  - [Migrating data from the Metadata Standards Directory](#migrating-data-from-the-metadata-standards-directory)

## Managing users

You can use `dbctl.py` to perform actions on the User database not available
through the Metadata Standards Catalog interfaces. This separation is a security
measure.

By default, the script looks for the User database following location, relative
to the script:

  - *NIX: `instance/data/users.json`
  - Windows: `instance\data\users.json`

You can change where the script looks with the `-u`/`--user-db` option:

```bash
./dbctl.py -u path/to/user-db <action>
```

### Adding API users

To add a new API user, run the script with `add-api-user` action and three
arguments:

```bash
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

### Blocking malicious users

To block or unblock a user, use one of the following actions:

```.bash
./dbctl.py block-user "user ID"
./dbctl.py block-api-user "user ID"
./dbctl.py unblock-user "user ID"
./dbctl.py unblock-api-user "user ID"
```

The user ID must correspond to a `userid` value in the database.

## Backing up and restoring the database

This repository contains a folder `db` containing a set of records in YAML
format. This was originally used for migrating data into the Catalog from its
predecessor, the Metadata Standards Directory. The method used is described at
the end of this document.

It is possible to compile these individual files into a single JSON file that
can be used as the Catalog's Main database. Conversely, the Main database can be
decompiled into individual YAML files for easier inspection. These functions
could be used as part of a backup and restore procedure, with the `db` folder in
this repository acting as a backup for the live data.

By default, the script looks for the Main database following location, relative
to the script:

  - *NIX: `instance/data/db.json`
  - Windows: `instance\data\db.json`

It will also assume you want to use the `db` folder and its subfolders for the
YAML files.

You can change the path the script uses for the database file and YAML folder
with the `-d`/`--db` and `-f`/`--folder` options respectively:

```bash
./dbctl.py -d path/to/main-db -f path/to/yaml-folder <action>
```

### Backing up

To turn the Catalog's Main database from a single JSON file into individual YAML
records, run the database control script with the `dump` action:

```bash
./dbctl.py dump
```

If this would overwrite an existing set of YAML files, you have the choice of
replacing (erasing) them, displacing them (backing them up to `db0`, `db1`,
`db2`, etc.), or cancelling.

### Restoring

To convert the YAML files in the `db` folder (or another equivalent collection)
into a single JSON file for use as the Catalog's Main database, run the database
control script with the `compile` action:

```bash
./dbctl.py compile
```

## Updating the subject ontology

To update the RDF subject thesaurus used by the Catalog, run the database
control script with the `vocab` action:

```bash
./dbctl.py vocab
```

There are no effective command-line options here; in the absence of any demand
for configurability, the paths are hard-coded.

What happens is that the script will look for an adjacent file called
`unesco-thesaurus.ttl` and parse it if available. Otherwise it will download a
fresh copy of the [UNESCO Vocabulary] and parse that instead. It will strip out
unused triples and (in a somewhat hackish manner) enable the domains and
microthesauri to be traversed as if they were higher level concepts. It will
save the result as `simple-unesco-thesaurus.ttl`; if you are running `dbctl.py`,
in the same directory as `serve.py`, this file will already be in the correct
place, otherwise you should manually move it to the same directory as
`serve.py`.

[UNESCO Vocabulary]: http://vocabularies.unesco.org/browser/rest/v1/thesaurus/data?format=text/turtle

## Migrating data from the Metadata Standards Directory

### Setting up

If you want to re-run the process for converting the records from the Metadata
Standards Directory for use with the Metadata Standards Catalog, the easiest way
to proceed is to set up local copies of this repository and that of the Metadata
Standards Directory within neighbouring folders:

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

The migration process is handled by the Python script `migrate.py`. The only
thing you need installed beyond the standard installation of [Python 3] is the
non-standard library [PyYAML]. You can install this quite easily using the `pip`
utility.

(Ubuntu/Debian users may prefer to install the `python3-yaml` package.)

Since the conversion has already been performed in this repository, you might
prefer to set up a third directory for testing, and copy the `migrate.py` script
and `jacs2unesco.yml` file into it:

```
rda-dev/
    metadata-catalog-dev/
    metadata-catalog-test/
        migrate.py
        jacs2unesco.yml
    metadata-directory/
```

### Migrating the records

Within your testing folder, run the Python script `migrate.py`. On UNIX systems,
you should be able to use it directly:

```bash
./migrate.py
```

Otherwise you might need to invoke `python` or `python3`:

```bash
python3 migrate.py
```

If you have set up your files and folders as above, this should be all you need
to do. If, however, you need to change where the script looks for the
`metadata-directory` folder or the mapping from Directory disciplines to Catalog
subject keywords (i.e. `jacs2unesco.yml`), or change where the script writes out
its YAML files, you can use command line options. For details, run the following
command:

```bash
./migrate.py --help
```

After running the script, you should have the following new files and folders:

  - `db/`: contains a further 5 folders in which the migrated data are
    stored in `.yml` files. (The endorsements folder will be empty)
  - `disciplines.yml`: a report of all the disciplines uses in the Metadata
    Standards Directory, useful if you want to write your own mapping to a
    different controlled vocabulary.
  - `migration-log.yml`: a report of things that might need to be tidied up
    manually, e.g. unrecognized disciplines or sponsor organizations.
