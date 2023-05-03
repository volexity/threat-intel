# OneNoteExtractor
# Copyright (C) 2023 Volexity, Inc.

"""Example script showing use of OneNoteExtractor."""

import argparse
import os
import textwrap

from . import OneNoteExtractor
from ._version import __version__


def run():
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description=textwrap.dedent(
            f"""
            Volexity OneNoteExtractor | Extract metadata and/or files from OneNote files
            Version {__version__}
            https://www.volexity.com
            (C) 2023 Volexity, Inc. All rights reserved"""
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("target_file", type=str, help="Input file to parse")
    parser.add_argument("--extract-meta", help="If set, extracts metadata from .one file",
                        action="store_true")
    parser.add_argument("--extract-files", help="If set, extracts files from .one file",
                        action="store_true")
    parser.add_argument("--output-directory", help="Where should extracted objects be saved to?",
                        default=os.getcwd())
    parser.add_argument("--password", help="Password to use to extract files from encrypted "
                        "onenote files", action="store")
    parser.add_argument("--version", action="version", help="print the version of one-extract",
                        version=__version__)
    args = parser.parse_args()

    if not args.extract_meta and not args.extract_files:
        exit("Must either attempt to extract metadata or files.")

    with open(args.target_file, 'rb') as infile:
        data = infile.read()

    document = OneNoteExtractor(data=data, password=args.password)
    # Extract subfile objects from the document
    if args.extract_files:
        for index, file_data in enumerate(document.extract_files()):
            bn = os.path.basename(args.target_file)
            target_path = os.path.join(args.output_directory, f"{bn}_{index}.extracted")
            print(f"Writing extracted files to: {target_path}")
            with open(target_path, 'wb') as outf:
                outf.write(file_data)

    # Extract metadata from the document
    if args.extract_meta:
        for on_meta in document.extract_meta():
            print(on_meta)
