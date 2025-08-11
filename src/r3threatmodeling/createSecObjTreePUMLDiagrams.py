#!/usr/bin/env python3

# from lib2to3.pygram import pattern_symbols
from pathvalidate import sanitize_filename
import os
import argparse
import traceback

from .threatmodel_data import *


def generate(tmo, outputDir):
    """Generate one PlantUML file per security objective (pure Python)."""
    os.makedirs(outputDir, exist_ok=True)
    for secObj in getattr(tmo, 'securityObjectives', []) or []:
        lines = ["@startuml", f'title {secObj._id} - {getattr(secObj, "title", "")}',
                 f'class {secObj._id} {{', '}}']
        # Contributes to relationships
        for parent in getattr(secObj, 'contributesTo', []) or []:
            try:
                parent_id = parent._id
            except AttributeError:
                parent_id = str(parent)
            lines.append(f'{secObj._id} --> {parent_id} : contributes to')
        lines.append('@enduml')
        out_file_name = os.path.join(outputDir, secObj._id + '.puml')
        with open(out_file_name, 'w') as f:
            f.write("\n".join(lines))
    for child in tmo.getDescendantsTM():
        generate(child, outputDir)

def main():

    CLI=argparse.ArgumentParser()

    CLI.add_argument(
        "--rootTMYaml",
        default = None,
        required=True,
        type=open
    )

    CLI.add_argument(
        "--YAMLprefix",  
        default = "",
        required=False
    )

    CLI.add_argument(
    "--outputDir", 
    default = "build/img/",
    required=False
    )

    args = CLI.parse_args()

    tmo = ThreatModel(args.rootTMYaml)
    outputDir = args.outputDir
    generate(tmo, outputDir)

    return 

if __name__ == "__main__":
    main()