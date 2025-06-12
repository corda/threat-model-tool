#!/usr/bin/env python3

import argparse
import os
import pathlib
import yaml # Ensure PyYAML or ruamel.yaml is installed
from r3threatmodeling.threatmodel_data import ThreatModel # Assuming ThreatModel can be initialized with a file object

def dir_path(path_str):
    """Helper function for argparse to validate if the input path is a directory."""
    if os.path.isdir(path_str):
        return path_str
    else:
        raise argparse.ArgumentTypeError(f"readable_dir:{path_str} is not a valid path")

def main():
    parser = argparse.ArgumentParser(description="Find and parse root threat model YAML files in a directory.")
    parser.add_argument(
        "--TMDirectory",
        default="threatModels",
        type=dir_path,
        required=False,
        help="The parent directory containing threat model subdirectories."
    )

    args = parser.parse_args()
    tm_directory_path = pathlib.Path(args.TMDirectory)
    
    found_root_tms = []

    print(f"Scanning directory: {tm_directory_path.resolve()}")

    for item in tm_directory_path.iterdir():
        if item.is_dir():
            # Potential threat model directory. Check for a YAML file with the same name.
            potential_tm_yaml_file = item / (item.name + ".yaml")
            if potential_tm_yaml_file.is_file():
                print(f"Found root threat model YAML: {potential_tm_yaml_file}")
                try:
                    with open(potential_tm_yaml_file, 'r') as f:
                        # Parse the YAML file into a ThreatModel object
                        tm = ThreatModel(f) 
                        found_root_tms.append({
                            "name": tm.id, # or tm.title, depending on what's more appropriate
                            "path": str(potential_tm_yaml_file.resolve()),
                            "object": tm 
                        })
                        print(f"Successfully parsed: {tm.id if hasattr(tm, 'id') else potential_tm_yaml_file.name}")
                except Exception as e:
                    print(f"Error parsing {potential_tm_yaml_file}: {e}")

    if found_root_tms:
        print("\n--- Summary of Parsed Root Threat Models ---")
        for tm_info in found_root_tms:
            print(f"- Name: {tm_info['name']}, Path: {tm_info['path']}")
    else:
        print("\nNo root threat models found in the specified directory.")

if __name__ == "__main__":
    main()
