import os
import sys
import yaml

# Template string for the YAML content
yaml_template = """ID: {id}
parent: {parent}
scope:
  assets: 
analysis: TODO
threats: 
"""

# Check if the YAML file path is provided as a console parameter
if len(sys.argv) != 2:
    print("Usage: python createChildrenUtil.py <path_to_CBUAE_PHASE2.yaml>")
    sys.exit(1)

# Define the path to the CBUAE_PHASE2.yaml file from the console parameter
cbuae_phase2_yaml_path = sys.argv[1]
base_directory = os.path.dirname(cbuae_phase2_yaml_path)

# Derive the parent from the name of the input file
parent_name = os.path.splitext(os.path.basename(cbuae_phase2_yaml_path))[0]

# Load the CBUAE_PHASE2.yaml file
with open(cbuae_phase2_yaml_path, 'r') as file:
    data = yaml.safe_load(file)

# Extract the children
children = data.get('children', [])

# Print the children field for debugging
print("Children field:", children)

# Ensure children is a list of dictionaries with an 'ID' field
if not isinstance(children, list) or not all(isinstance(child, dict) and 'ID' in child for child in children):
    print("Error: 'children' should be a list of dictionaries with an 'ID' field.")
    sys.exit(1)

# Extract the IDs from the children
child_ids = [child['ID'] for child in children]

# Create folders and YAML files for each child
for child in child_ids:
    child_folder_path = os.path.join(base_directory, child)
    child_yaml_path = os.path.join(child_folder_path, f"{child}.yaml")
    
    # Create the folder if it doesn't exist
    if not os.path.exists(child_folder_path):
        os.makedirs(child_folder_path)
        print(f"Created folder: {child_folder_path}")
    else:
        print(f"Folder already exists: {child_folder_path}")
    
    # Create the YAML file with the template content only if it doesn't exist
    if not os.path.exists(child_yaml_path):
        yaml_content = yaml_template.format(id=child, parent=parent_name)
        
        # Write the YAML file
        with open(child_yaml_path, 'w') as yaml_file:
            yaml_file.write(yaml_content)
            print(f"Created YAML file: {child_yaml_path}")
    else:
        print(f"YAML file already exists: {child_yaml_path}")