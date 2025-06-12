import argparse
import yaml
import os
from r3threatmodeling.threatmodel_data import ThreatModel
import sys 

def find_root_yaml(filepath):
    """
    Recursively finds the root YAML file by traversing the 'parent' attribute.
    Returns the filepath of the root YAML file.
    """
    current_filepath = filepath
    while True:
        try:
            with open(current_filepath, 'r') as f:
                data = yaml.safe_load(f)
                if 'parent' not in data:
                    return current_filepath
                parent_name = data['parent']
                parent_dir = os.path.dirname(os.path.dirname(current_filepath))
                current_filepath = os.path.join(parent_dir, f"{parent_name}.yaml")
        except FileNotFoundError:
            print(f"Error: Parent file not found: {current_filepath}")
            return None  # Or raise an exception
        except Exception as e:
            print(f"Error parsing YAML: {e}")
            return None

def parse_threat_model(filepath):
    """
    Parses the YAML file and returns the threat model object.
    """
    try:
        with open(filepath, 'r') as f:
            threat_model = ThreatModel(f) 
            return threat_model
    except FileNotFoundError:
        print(f"Error: File not found: {filepath}")
        return None
    except Exception as e:
        print(f"Error parsing YAML: {e}")
        return None

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Find root YAML file and parse threat model.')
    parser.add_argument('--tmYAMLfile', type=str, help='Path to the threat model YAML file.')

    args = parser.parse_args()

    if not args.tmYAMLfile:
        print("Error: Please provide the path to the threat model YAML file using the --tmYAMLfile argument.")
        exit(1)

    # Example usage:
    filepath = args.tmYAMLfile  # Replace with your file path
    
    root_filepath = find_root_yaml(filepath)
    
    if root_filepath:
        print(f"Root YAML file: {root_filepath}")
        threat_model = parse_threat_model(root_filepath)
        if threat_model:
            print("Threat Model Parsed Successfully:")
            print(threat_model.id) # print the threat model object
            sys.exit(0)
        else:
            print("Failed to parse threat model.")
    else:
        print("Could not find root YAML file.")
    sys.exit(-1)