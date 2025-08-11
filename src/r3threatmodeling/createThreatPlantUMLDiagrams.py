#!/usr/bin/env python3

# from lib2to3.pygram import pattern_symbols
# from pathvalidate import sanitize_filename
import os
import argparse
import traceback

from .threatmodel_data import *



def generate(tmo, outputDir):
    """Generate per-threat PlantUML attack tree skeletons (pure Python)."""
    os.makedirs(outputDir, exist_ok=True)
    for threat in tmo.getAllDown("threats"):
        lines = ["@startuml", '! Simple placeholder diagram (template removed)']
        title = getattr(threat, 'title', threat._id)
        lines.append(f'title {threat._id} - {title}')
        # Basic node with impacted security objectives
        impacted = getattr(threat, 'impactedSecObj', []) or []
        if impacted:
            for so in impacted:
                try:
                    so_id = so._id
                except AttributeError:
                    so_id = str(so)
                lines.append(f':{so_id}:')
        lines.append('@enduml')
        out_file_name = os.path.join(outputDir, threat._id + '.puml')
        with open(out_file_name, 'w') as f:
            f.write("\n".join(lines))

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



