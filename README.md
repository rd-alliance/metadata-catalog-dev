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
need the non-standard library [TinyDB]. (This has not been packaged for Ubuntu
so you will probably want to install it with `python3-pip`.)

[TinyDB]: http://tinydb.readthedocs.io/

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

## Running the prototype Metadata Standards Catalog

To run the prototype Catalog, you will need [TinyDB] and [Flask]. It is
currently compatible with Flask 0.10 (this is what `python3-flask` gives you in
Ubuntu LTS releases).

[Flask]: http://flask.pocoo.org/

Open up a fresh terminal/command prompt (as it will block the command line for
as long as the script is running) and run the [Python 3] script `serve.py`:

~~~{.bash}
./serve.py
~~~

You should then be able to access the Catalog in your Web browser using the URL
the script shows you, e.g. <http://127.0.0.1:5000/>.
