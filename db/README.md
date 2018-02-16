---
title: Metadata Standards Catalog Database
---

# Introduction

This directory contains a snapshot of the Metadata Standards Catalog database.
It is staging area intended for migrating records to the Catalog from the
Metadata Standards Directory.

It is not yet decided if there will be a role for the files herein once the
Catalog has been launched, since the Catalog database will evolve independently.

# Entity model

The primary focus of the Metadata Standards Catalog is on metadata schemes, so
the main entity is the **Metadata Scheme**. Contrary to previous incarnations of
this catalog, this model does not make a hard distinction between “top level”
schemes and profiles.

Secondary entities are used to express information about the scheme in terms
of its relationships:

  - **Organization** (e.g. funder, standards body)
  - **Tool** (e.g. software that may be used to create records using the scheme)
  - **Mapping** (e.g. crosswalk, comparative analysis)
  - **Endorsement** (e.g. recommendation from RDA group, publisher)

Within this directory, each entity in the model is represented by subdirectory:
`endorsements`, `mappings`, `metadata-schemes`, `organizations` and `tools`
respectively. Within each subdirectory, each instance of the entity (hence each
record in the database) is represented by a YAML file. The file name is a slug
(see below) derived from the name or title, with a `.yml` extension.

When adjusting these files by hand, please be aware that they will be converted
to JSON for use in the Catalog.

## Common administrative elements

Records in the Catalog have some fields that are included for administrative
purposes, rather than reflecting information about the instance being described.
The following list should not be considered exhaustive, though every effort will
be made to record new fields as they are introduced.

### Slug

This field is used to generate file names when the database is serialized to
individual files (as was the case with the Metadata Standards Directory data).
The value should consist of lowercase letters, numbers and hyphens, and be
limited to 71 characters.

~~~{.yaml}
slug: my-metadata-scheme
~~~

# Metadata Scheme

## Example record

The following shows a complete (dummy) record for a metadata scheme, expressed
in YAML.

~~~{.yaml}
title: My metadata scheme
identifiers:
  - id: "msc:m1"
    scheme: RDA-MSCWG
versions:
  - number: 1.0
    issued: 2016-09-15
description: >
    This scheme is used to document itself.
keywords:
  - keyword 1
  - keyword 2
dataTypes:
  - url: http://
    label: keyword
locations:
  - url: http://...
    type: website
  - url: http://...
    type: RDA-MIG
samples:
  - url: http://...
    title: Sample record 1
  - url: http://...
    title: Sample record 2
relatedEntities:
  - id: "msc:g1"
    role: maintainer
  - id: "msc:m2"
    role: parent scheme
  - id: "msc:e1"
    role: endorsement
~~~

## Elements

The example above shows the scheme serialized as YAML. It may be converted
straightforwardly to JSON. It is a design decision of the data model that within
a given array, an element can occur at most once as a key.

When serializing as XML, note that the elements that contain lists have plural
names. Each item in the list should be wrapped in a (repeatable) element with
the singular version of the element name, as in the following example:

~~~{.xml}
<sample>
  <url>http://...</url>
  <title>Sample record 1</title>
</sample>
<sample>
  <url>http://...</url>
  <title>Sample record 2</title>
</sample>
~~~

The elements making up this part of the data model are as follows.

### Title

The full, human understandable name of the metadata scheme.

*Notes*

  * If the scheme is known by an abbreviation, put this at the start of the
    title, then give the expanded form in parentheses, e.g. “SDMX (Statistical Data and Metadata Exchange)”.
  * If the title is in English, use title case, i.e. give each significant word
    a capital letter. Do not use an irregular case to indicate how an
    abbreviation was defined, e.g. do not write “Statistical Data and Metadata eXchange”.

### Identifiers

This element contains a list of associative arrays. Each array represents an
identifier:

  * **id**  
    The identifier itself.

  * **scheme**  
    A keyword indicating the scheme from which the identifier is drawn. Possible
    values:
      + *RDA-MSCWG*: Internal identifier scheme for the MSC.
      + *DOI*: Digital Object Identifier.

*Notes*

  * If a keyword exists for the identifier scheme, the **scheme** element must
    be used with the appropriate keyword. Otherwise, the **scheme** element is
    optional. The database will be reviewed periodically for non-standard
    keywords, which will be considered for inclusion in the controlled list.

### Versions

This element contains a list of associative arrays. Each array represents a
version:

  * **number**  
    The number, code or other string used to identify the version.

  * **available**  
    The date on which this version was made available as a draft or proposal.
    A version with an **available** date but no **issued** date is assumed not
    to be approved by its maintainer for use. (This element is provided to
    allow schemes or versions to be entered into the MSC prior to official
    approval; retrospectively uncovering this information for versions that
    have been issued is not encouraged.)

  * **issued**  
    The date on which the version was released or published. This also implies
    the date on which the version was approved for use by its maintainer,
    unless an explicit **valid** date is also given.

  * **valid**  
    A version of a scheme is assumed to be approved for use by its maintainer
    from its **issued** date until the **issued** date of a subsequent version.
    If this is not the case, (for example, where multiple versions are
    approved simultaneously), **valid** expresses the period for which a version
    is approved for use. A single date indicates that the version is still
    approved for use, despite the issue of subsequent versions. The second date
    in a range indicates the date on which approval was withdrawn.

  * Other elements as required.

*Notes*

  * Omit any initial “v”, “v.” or “ver.” from version numbers.
  * Provide the dates in ISO format, i.e. yyyy, yyyy-mm, or yyyy-mm-dd.
    To specify a range, provide two dates separated by a slash, e.g.
    yyyy-mm-dd/yyyy-mm-dd.
  * Other elements of the wider scheme (not including **versions**) may be
    provided within the array. The value or values given override the ones given
    at the top level, for the given version only. For example, if the title of
    a standard changed between versions 0.8 and 1.0, this would be expressed as
    follows:

    ~~~{.yaml}
    title: Current Title
    versions:
      - number: 1.0
        issued: 2015
      - number: 0.8
        issued: 2012
        title: Previous Title
    ~~~

### Description

A few sentences describing the nature of the standard and for what it is meant
to be used.

If any of the information in the remainder of the record needs be clarified,
perhaps because the reality is more nuanced than the coarse semantics provide
for, then an explanation can be given here.

*Notes*

  * This could indicate if the scheme is used to create standalone metadata
    records, or insert metadata into data files, or is in fact a data format
    that includes metadata elements.
  * This could indicate the intended use cases satisfied by the scheme, e.g.
    discovery, exchange.
  * If many keywords are used to describe the disciplinary scope of the scheme,
    this could pick out the disciplines in which it is most popular.
  * If the scheme is a profile, this could clarify whether it closely follows
    one parent scheme, or mixes together elements from a variety of parent
    schemes.
  * This could indicate if the scheme is tied to a particular serialization
    (e.g. XML) or could be expressed in various ways (e.g. RDF).

### Keywords

This element contains a list of terms indicating the disciplinary scope of the
scheme. The terms must be drawn from the [UNESCO Thesaurus]; the preferred
English labels of Domains, MicroThesauri and Concepts may be used. (If a label
is used at more than one level, the broadest one will be inferred.)

[UNESCO Thesaurus]: http://vocabularies.unesco.org/browser/thesaurus/en/

Schemes with no particular disciplinary focus should be given the special
keyword *Multidisciplinary*.

*Notes*

  * The MSC makes use of the hierarchical nature of the taxonomy. Tagging
    a scheme with a particular term will make it show up in searches for the
    term itself, plus narrower and broader terms, but not disjoint terms.
  * With the above in mind, provide as few terms as possible to describe the
    subject areas in which the scheme is most used and useful. In some cases,
    it may be better to use a broader term even if not all of the available
    narrower terms apply.

### DataTypes

This element contains a list of associative arrays. Each array represents one of
the data types most commonly described by metadata records that conform to this
scheme:

  * **url**  
    Absolute URL pointing to an entry in a data type registry.

  * **label**  
    Human-readable term.

The MSC will take a “folksonomic” approach to the human-readable values for this
element: users will be able to supply any value but will be encouraged to reuse
values already in the database. Trivially different values may be
merged/normalized by the MSC editors, unless clarified with a URL.

### Locations

This element contains a list of associative arrays. Each array represents a
location where further information about the scheme may be accessed:

  * **url**  
    Relative or absolute URL of the Web resource.

  * **type**  
    A keyword describing the type of resource. Possible values:
      + *RDA-MIG*: Normalized specification type as devised by the RDA
        metadata groups.
      + *DTD*: Specification in the form of an XML Document Type Description.
      + *XSD*: Specification in the form of an XML Schema Definition.
      + *RDFS*: Specification in the form of RDF triples.
      + *document*: Non-machine-readable document (e.g. HTML, PDF) describing
        the specification.
      + *website*: The home page of a website dedicated to the scheme, or a web
        page collecting resources relevant to the scheme.

*Notes*

  * Normalized specifications hosted by the MSC should be specified using a
    relative URL.

### Samples

This element contains a list of associative arrays. Each represents a metadata
record that conforms to the current scheme:

  * **url**  
    The URL of the sample record. For samples hosted by the MSC, the URL should
    be specified in relative form.

  * **title**  
    The value of the title element from the sample record, or an equivalent
    short summary of what the sample record describes.

### RelatedEntities

This element contains a list of associative arrays. Each represents another
entity in the MSC database:

  * **id**  
    The internal MSC ID for the entity.

  * **role**  
    The manner of the relationship between the entity and the scheme. Possible
    values:
      + *parent scheme*: The current scheme is a profile of the specified
        scheme. In practice, this means either that the current scheme
        explicitly “borrows” elements from the parent scheme, or that all
        instances of the current scheme would be valid instances of the parent
        scheme.
      + *maintainer*: The specified organization is responsible for the current
        specification and for future developments.
      + *funder*: The specified organization funded (in whole or in part) the
        development of the scheme, or helps to fund its continued maintenance.
      + *user*: The specified organization or service uses the current scheme
        in order to achieve its goals.
      + *endorsement*: The current scheme (or version) is endorsed by the
        specified endorsement. The originator of the endorsement must not be the
        *maintainer*.

## Conformance levels

The data model recognizes these three levels of conformance:

 #. **Valid**  
    The record contains at least one of the elements described above. All such
    elements used in the record have the expected values as described above.
    Elements with plural names are not repeated within a given array. (For the
    purposes of extensibility, valid records may contain elements not described
    above.)

 #. **Useful**  
    The record contains at least a **title**, an **identifier**, a
    **description**, a **keyword** and a **location**.

 #. **Complete**  
    The record contains all the above elements. Elements representing lists
    have at least one member of that list.

# Organization

## Example record

The following shows a complete (dummy) record for an organization, expressed
in YAML.

~~~{.yaml}
name: The Organization
identifiers:
  - id: "msc:g1"
    scheme: RDA-MSCWG
types:
  - standards body
locations:
  - url: http://...
    type: website
~~~

## Elements

The elements making up this part of the data model are as follows.

### Name

The full name of the organization as it is usually given.

### Identifiers

This element contains a list of associative arrays. Each array represents an
identifier:

  * **id**  
    The identifier itself.

  * **scheme**  
    A keyword indicating the scheme from which the identifier is drawn. The
    possible values are given under the “Metadata Scheme” entity above.

*Notes*

  * The same considerations apply as for “Metadata Scheme”.

### Types

This element contains a list of terms that describe the organization. Possible
values:

  * *standards body*: The organization's primary activities are developing,
    agreeing, publishing, and maintaining standards that address the needs of
    adopters from multiple independent groups.
  * *archive*: The organization's primary activity is archiving research data.
  * *professional group*: The organization is a learned society or other
    professional grouping that promotes a particular discipline, profession, or
    a family of related disciplines or professions.
  * *coordination group*: The organization exists to coordinate the activities
    of otherwise independent groups to achieve a specific aim.

### Locations

This element contains a list of associative arrays. Each array represents a
location where further information about the mapping may be accessed:

  * **url**  
    Relative or absolute URL of the Web resource.

  * **type**  
    A keyword describing the type of resource. Possible values:
      + *website*: The home page of the organization.
      + *email*: An email address for the organization suitable for enquiries about metadata standards or tools.

## Conformance levels

The data model recognizes these three levels of conformance:

 #. **Valid**  
    The record contains at least one of the elements described above. All such
    elements used in the record have the expected values as described above.
    Elements with plural names are not repeated within a given array. (For the
    purposes of extensibility, valid records may contain elements not described
    above.)

 #. **Useful**  
    The record contains at least a **name** and an **identifier**.

 #. **Complete**  
    The record contains all the above elements. Elements representing lists
    have at least one member of that list.

# Tool

## Example record

The following shows a complete (dummy) record for a tool, expressed in YAML.

~~~{.yaml}
title: My tool
identifiers:
  - id: "msc:t1"
    scheme: RDA-MSCWG
versions:
  - number: 1.0
    date: 2016-09-15
creators:
  - fullName: Jane Doe
    givenName: Jane
    familyName: Doe
description: >
    This tool is used for writing metadata records.
types:
  - terminal (Windows)
  - graphical (Windows)
  - web service
  - web application
locations:
  - url: http://...
    type: website
relatedEntities:
  - id: "msc:m1"
    role: supported scheme
~~~

## Elements

The elements making up this part of the data model are as follows.

### Title

The full, human understandable name of the tool.

*Notes*

  * The same considerations apply as for “Metadata Scheme”.

### Identifiers

This element contains a list of associative arrays. Each array represents an
identifier:

  * **id**  
    The identifier itself.

  * **scheme**  
    A keyword indicating the scheme from which the identifier is drawn. The
    possible values are given under the “Metadata Scheme” entity above.

*Notes*

  * The same considerations apply as for “Metadata Scheme”.

### Versions

This element contains a list of associative arrays. Each array represents a
version:

  * **number**  
    The number, code or other string used to identify the version.

  * **date**  
    The date on which the version was published.

  * Other elements as required.

*Notes*

  * The same considerations apply as for “Metadata Scheme”.

### Creators

This element contains a list of associative arrays. Each array represents a
person or organization responsible for creating, maintaining, or approving the
tool (the emphasis here is on establishing provenance/responsibility rather
than a strict understanding of creation):

  * **fullName**  
    The full name of the person or organization as it is usually given.
  * **givenName**  
    The given name(s) of the person.
  * **familyName**  
    The family name of the person.

*Notes*

  * If all three elements are provided, the value of **fullName** will be used
    for display.
  * If a maintaining organization has an entry in the MSC, it should be given
    under **relatedEntities** with type *maintainer* rather than here.

### Description

A short description of the intended use of the tool, and its capabilities.

### Types

This element contains a list of terms that describe how a user interacts with
the tool. Possible values:

  * *terminal (\<platform\>)*: Installed locally on a computer and accessed
    via the command prompt, terminal, or command line. The supported platform(s)
    should be given in parentheses.
  * *graphical (\<platform\>)*: Installed locally on a computer and run as a
    windowed application (or via a browser). The supported platform(s) should
    be given in parentheses.
  * *web service*: Accessible on the Web to scripts, programs and command-line
    tools (usually as a SOAP or RESTful service).
  * *web application*: Accessible on the Web via an interface aimed at humans
    (usually HTML pages).

### Locations

This element contains a list of associative arrays. Each array represents a
location where further information about the tool may be accessed:

  * **url**  
    Relative or absolute URL of the Web resource.

  * **type**  
    A keyword describing the type of resource. Possible values:
      + *document*: Non-machine-readable document (e.g. HTML, PDF) describing
        the tool (e.g. user manual, help page).
      + *website*: The home page of a website dedicated to the tool, from which
        the tool may be downloaded, or a web page collecting resources relevant to the tool.
      + *application*: The interface for the Web application itself.
      + *service*: The Web service endpoint (to which requests are sent).

### RelatedEntities

This element contains a list of associative arrays. Each represents another
entity in the MSC database:

  * **id**  
    The internal MSC ID for the entity.

  * **role**  
    The manner of the relationship between the entity and the scheme. Possible
    values:
      + *supported scheme*: The tool accepts metadata that conforms to the
        scheme as input, or outputs such metadata.
      + *maintainer*: The specified organization is responsible for the current
        version of the tool and for future developments.
      + *funder*: The specified organization funded (in whole or in part) the
        development of the tool, or helps to fund its continued maintenance.

## Conformance levels

The data model recognizes these three levels of conformance:

 #. **Valid**  
    The record contains at least one of the elements described above. All such
    elements used in the record have the expected values as described above.
    Elements with plural names are not repeated within a given array. (For the
    purposes of extensibility, valid records may contain elements not described
    above.)

 #. **Useful**  
    The record contains at least a **title**, an **identifier**, a
    **description**, a **keyword** and a **location**.

 #. **Complete**  
    The record contains all the above elements. Elements representing lists
    have at least one member of that list.

# Mapping

The mappings recorded in the MSC are not guaranteed to work in all instances,
but there is an implication that they have been authored or reviewed by a human.
Automatically generated mappings should not be added until they have been
checked for accuracy.

## Example record

The following shows a complete (dummy) record for a metadata mapping, expressed
in YAML.

~~~{.yaml}
identifiers:
  - id: "msc:c1"
    scheme: RDA-MSCWG
versions:
  - number: 1.0
    date: 2016-09-15
creators:
  - fullName: Jane Doe
    givenName: Jane
    familyName: Doe
description: >
    A crosswalk tailored for Polar Year data.
locations:
  - url: http://...
    type: library (PHP)
relatedEntities:
  - id: "msc:m1"
    role: input scheme
  - id: "msc:m2"
    role: output scheme
~~~

## Elements

The elements making up this part of the data model are as follows.

### Identifiers

This element contains a list of associative arrays. Each array represents an
identifier:

  * **id**  
    The identifier itself.

  * **scheme**  
    A keyword indicating the scheme from which the identifier is drawn. The
    possible values are given under the “Metadata Scheme” entity above.

*Notes*

  * The same considerations apply as for “Metadata Scheme”.

### Versions

This element contains a list of associative arrays. Each array represents a
version:

  * **number**  
    The number, code or other string used to identify the version.

  * **date**  
    The date on which the version was published.

  * Other elements as required.

*Notes*

  * The same considerations apply as for “Metadata Scheme”.

### Creators

This element contains a list of associative arrays. Each array represents a
person or organization responsible for creating, maintaining, or approving the
mapping (the emphasis here is on establishing provenance/responsibility rather
than a strict understanding of creation):

  * **fullName**  
    The full name of the person or organization as it is usually given.
  * **givenName**  
    The given name(s) of the person.
  * **familyName**
    The family name of the person.

*Notes*

  * If all three elements are provided, the value of **fullName** will be used
    for display.
  * If a maintaining organization has an entry in the MSC, it should be given
    under **relatedEntities** with type *maintainer* rather than here.

### Description

A short description of the intended use of the mapping, including any
assumptions or simplifications used, or any known limitations.

*Notes*

  * This could indicate if the mapping has been tailored to the outputs or
    inputs of specific repositories or services.
  * This could indicate if certain parts of the input or output schemes have
    been ignored.
  * This could indicate if specific conventions in the input scheme are
    preferred (or necessary).
  * This could recommend steps to be taken before or after applying the mapping
    in order to improve results.

### Locations

This element contains a list of associative arrays. Each array represents a
location where further information about the mapping may be accessed:

  * **url**  
    Relative or absolute URL of the Web resource.

  * **type**  
    A keyword describing the type of resource. Possible values:
      + *document*: Non-machine-readable document (e.g. HTML, PDF) describing
        the mapping.
      + *library (\<language\>)*: Machine-actionable code for performing the
        mapping. Use this if the code is intended to be called by a program
        rather than run directly by the user. The programming/scripting
        language should be given in parentheses.
      + *executable (\<platform\>)*: Machine-actionable code for performing the
        mapping. Use this if the code is intended to be run directly by the
        user. The supported platform(s) should be given in parentheses.

### RelatedEntities

This element contains a list of associative arrays. Each represents another
entity in the MSC database:

  * **id**  
    The internal MSC ID for the entity.

  * **role**  
    The manner of the relationship between the entity and the mapping. Possible
    values:
      + *input scheme*: The scheme to which an input metadata record must
        conform.
      + *output scheme*: The scheme to which the output metadata records
        conform.
      + *maintainer*: The specified organization is responsible for the current
        version of the mapping and for future developments.
      + *funder*: The specified organization funded (in whole or in part) the
        development of the mapping, or helps to fund its continued maintenance.

## Conformance levels

The data model recognizes these three levels of conformance:

 #. **Valid**  
    The record contains at least one of the elements described above. All such
    elements used in the record have the expected values as described above.
    Elements with plural names are not repeated within a given array. (For the
    purposes of extensibility, valid records may contain elements not described
    above.)

 #. **Useful**  
    The record contains at least an **identifier**, a **location**, a
    **relatedEntity** of type *input scheme*, and a **relatedEntity** of type
    *output scheme*.

 #. **Complete**  
    The record contains all the above elements. Elements representing lists
    have at least one member of that list. The **relatedEntities** element
    contains at least one *input scheme* and one *output scheme*.

# Endorsement

This entity represents an endorsement to use the scheme by a person or
organization other than the maintainer of the scheme.

## Example record

The following shows a complete (dummy) record for an endorsement, expressed in YAML.

~~~{.yaml}
identifiers:
  - id: "msc:e1"
    scheme: RDA-MSCWG
valid: 2016-09-15
citation: Author, year, title, publication information
locations:
  - url: http://...
    type: document
relatedEntities:
  - id: "msc:m1"
    role: endorsed scheme
  - id: "msc:g1"
    role: originator
~~~

## Elements

The elements making up this part of the data model are as follows.

### Identifiers

This element contains a list of associative arrays. Each array represents an
identifier:

  * **id**  
    The identifier itself.

  * **scheme**  
    A keyword indicating the scheme from which the identifier is drawn. Possible
    values:
      + *RDA-MSCWG*: Internal identifier scheme for the MSC.
      + *DOI*: Digital Object Identifier.

*Notes*

  * If a keyword exists for the identifier scheme, the **scheme** element must
    be used with the appropriate keyword. Otherwise, the **scheme** element is
    optional. The database will be reviewed periodically for non-standard
    keywords, which will be considered for inclusion in the controlled list.

### Issued

The date on which the endorsement was made. Use of this element does not imply
that the originating organization reviews the endorsement for validity.

*Notes*

  * Provide the date in ISO format, i.e. yyyy, yyyy-mm, or yyyy-mm-dd.
  * If both **issued** and **valid** are given, **issued** is ignored.
  * To express a continuing endorsement of the standard, use **valid** instead.


### Valid

This can be either a single date or a date range.

A single date expresses when the endorsement was made, and implies that the
originating organization currently endorses the standard. (If that implication
is inappropriate, the date should be given under **issued** instead.)

If a date range is provided, the first date expresses when the endorsement was
made, and the second date expresses the date on which the endorsement was
withdrawn.

*Notes*

  * Provide the date in ISO format, i.e. yyyy, yyyy-mm, or yyyy-mm-dd.
    To specify a range, provide two dates separated by a slash, e.g.
    yyyy-mm-dd/yyyy-mm-dd.
  * If it is doubtful whether the organization still endorses the standard, use
    **issued** instead.

### Citation

A traditional formatted citation for the endorsement statement or a document
that contains it.

### Locations

This element contains a list of associative arrays. Each array represents a
location where further information about the endorsement may be accessed:

  * **url**  
    Relative or absolute URL of the Web resource.

  * **type**  
    A keyword describing the type of resource. Possible values:
      + *document*: Non-machine-readable document (e.g. HTML, PDF) containing
        the endorsement.

### RelatedEntities

This element contains a list of associative arrays. Each represents another
entity in the MSC database:

  * **id**  
    The internal MSC ID for the entity.

  * **role**  
    The manner of the relationship between the entity and the mapping. Possible
    values:
      + *endorsed scheme*: The scheme which is endorsed.
      + *originator*: The organization that made the endorsement.

*Note*

  * If only particular versions of a metadata standard are endorsed, this should
    be expressed by reciprocal relations in the metadata standard record.

## Conformance levels

The data model recognizes these three levels of conformance:

 #. **Valid**  
    The record contains at least one of the elements described above. All such
    elements used in the record have the expected values as described above.
    Elements with plural names are not repeated within a given array. (For the
    purposes of extensibility, valid records may contain elements not described
    above.)

 #. **Useful**  
    The record contains at least an **identifier**, a **location**, a
    **relatedEntity** of type *endorsed scheme*.

 #. **Complete**  
    The record contains at least one **identifier**, an **issued** or **valid**
    date, a **location**, a **relatedEntity** of type *endorsed scheme*. If a
    **relatedEntity** of type *originator* is not provided, a **citation** must
    be provided.
