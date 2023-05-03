# OneNoteExtractor

This is a quick Python script for extracting files and metadata from `.one` files. At the time of the creation (2023-01-20) of this script there appear to be no Python scripts that can extract files or metadata from objects

## Installation

To install OneNoteExtractor, we recommend using something like this:

`cd /path/to/onenoteextractor/ && python -m pip install .`

## Usage as a library

For examples of how to use OneNoteExtractor as a library, review the code in `cli.py`

## CLI usage

Following successful installation of OneNoteExtractor a new CLI utility will be available, for usage see:

`one-extract --help`

### Extract embedded files

`one-extract /path/to/file.one --extract-files`

### Display metadata

`one-extract /path/to/file.one --extract-meta`

### Extract embedded files from a password protected notebook with password 1234

`one-extract /path/to/file.one --extract-files --password 1234`

## Disclaimer

This is only intended as an interim solution, until someone with a greater understanding of the `.one` file format comes up with something more robust.

It was created in response to an uptick in malicious `.one` file extensions being delivered by various malspam actors.
