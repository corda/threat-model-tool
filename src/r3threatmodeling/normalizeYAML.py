#!/usr/bin/env python3

import os
from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap
from ruamel.yaml.compat import ordereddict
import argparse
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

yaml_rt = YAML(typ='rt')
yaml_rt.indent(mapping=2, sequence=4, offset=2)
yaml_rt.preserve_quotes = True

def com_insert(self, pos, key, value, comment=None):
    od = ordereddict()
    od.update(self)
    for k in od:
        del self[k]
    for index, old_key in enumerate(od):
        if pos == index:
            self[key] = value
        self[old_key] = od[old_key]
    if comment is not None:
        self.yaml_add_eol_comment(comment, key=key)

CommentedMap.insert = com_insert

def getPos(oDict, toFind):
    try:
        return list(oDict.keys()).index(toFind)
    except ValueError:
        return -1

def update_countermeasure_dict(cm_dict):
    if not isinstance(cm_dict, dict):
        return

    # Remove unused attributes
    unused_cm = ['guide', 'required', 'createTicket', 'sensitivity']
    for attr in unused_cm:
        if attr in cm_dict:
            cm_dict.pop(attr)

def update_threat_dict(threat_dict):
    if not isinstance(threat_dict, dict):
        return

    # Add title if missing
    if 'title' not in threat_dict:
        name = threat_dict.get('ID', 'Unknown').replace('_', ' ').replace('-', ' ').title()
        threat_dict['title'] = name
        logging.info(f"Added missing title to threat: {name}")
        
    # description -> attack rename
    if 'description' in threat_dict:
        if 'attack' not in threat_dict or not threat_dict['attack']:
             threat_dict['attack'] = threat_dict.pop('description')
        else:
             threat_dict.pop('description')

    # Add missing description to threat countermeasures
    if 'countermeasures' in threat_dict and threat_dict['countermeasures'] is not None:
        for cm in threat_dict['countermeasures']:
            if isinstance(cm, dict) and 'ID' in cm and 'description' not in cm:
                cm['description'] = cm.get('title', cm['ID'])

    # Remove unused
    unused_threat = [
        'WIP', 'toReview', 'Taxonomy group', 'generic', 'sensitivity',
        'lowPriority', 'guide', 'required', 'createTicket'
    ]
    for attr in unused_threat:
        if attr in threat_dict:
            threat_dict.pop(attr)

    # impacts -> impactedSecObj rename
    if 'impacts' in threat_dict:
        order = getPos(threat_dict, 'impacts')
        impactedSecObj = threat_dict['impacts']
        threat_dict.pop('impacts')
        if order != -1:
            threat_dict.insert(order, 'impactedSecObj', impactedSecObj)
        else:
            threat_dict['impactedSecObj'] = impactedSecObj

    # Migrate IDs to REFIDs in lists of references
    for list_field in ['impactedSecObj', 'threatActors', 'countermeasures', 'assets']:
        if list_field in threat_dict and threat_dict[list_field] is not None:
            for i in range(len(threat_dict[list_field])):
                item = threat_dict[list_field][i]
                if not isinstance(item, dict):
                    continue
                
                # Determine if it's a definition or a reference
                is_definition = any(k in item for k in ['description', 'title', 'attack', 'mitigation', 'inPlace', 'type'])

                if 'ID' in item and 'REFID' not in item:
                    if not is_definition:
                        val = item.pop('ID')
                        item['REFID'] = val
                elif 'REFID' in item:
                    if is_definition:
                        val = item.pop('REFID')
                        item['ID'] = val

    if 'countermeasures' in threat_dict and threat_dict['countermeasures']:
        for cm in threat_dict['countermeasures']:
            update_countermeasure_dict(cm)

        # Move countermeasures to the end
        cms = threat_dict.pop('countermeasures')
        threat_dict['countermeasures'] = cms

def update_tm_dict(tm_dict, file_path=None):
    # Add title if missing
    if 'title' not in tm_dict:
        if file_path:
            base = os.path.basename(file_path)
            name = os.path.splitext(base)[0]
            tm_dict['title'] = name.replace('_', ' ').replace('-', ' ').title()
            logging.info(f"Added missing title to {file_path}: {tm_dict['title']}")
        else:
            tm_dict['title'] = "Missing Title"

    # schemaVersion
    if 'schemaVersion' not in tm_dict:
        order = getPos(tm_dict, 'ID')
        if order != -1:
            tm_dict.insert(order + 1, 'schemaVersion', 2)
        else:
            tm_dict['schemaVersion'] = 2
    elif tm_dict['schemaVersion'] < 2:
        tm_dict['schemaVersion'] = 2

    # cleanup root
    unused_root = ['executiveSummaryText', 'jiraLink', 'status', 'diagram', 'references', 'lastReview']
    for attr in unused_root:
        if attr in tm_dict:
            tm_dict.pop(attr)

    if 'scope' in tm_dict and tm_dict['scope'] is not None:
        for skip in ['diagram', 'references']:
            if skip in tm_dict['scope']:
                tm_dict['scope'].pop(skip)
        
        if 'securityObjectives' in tm_dict['scope'] and tm_dict['scope']['securityObjectives'] is not None:
             for obj in tm_dict['scope']['securityObjectives']:
                 if 'lowPriority' in obj:
                     obj.pop('lowPriority')

    # children IDs
    if 'children' in tm_dict and tm_dict['children'] is not None:
        for i in range(len(tm_dict['children'])):
            child = tm_dict['children'][i]
            if isinstance(child, dict) and 'ID' in child and 'REFID' not in child:
                val = child.pop('ID')
                child['REFID'] = val

    # Add missing description to countermeasures
    if 'countermeasures' in tm_dict and tm_dict['countermeasures'] is not None:
        for cm in tm_dict['countermeasures']:
            if isinstance(cm, dict) and 'ID' in cm and 'description' not in cm:
                cm['description'] = cm.get('title', cm['ID'])

    # threats
    if 'threats' in tm_dict and tm_dict['threats']:
        for threat in tm_dict['threats']:
            update_threat_dict(threat)

def process_file_recursive(file_path, prefix="", processed=None, dry_run=False):
    if processed is None:
        processed = set()
    
    abs_path = os.path.abspath(file_path)
    if abs_path in processed:
        return
    processed.add(abs_path)
    
    logging.info(f"Normalizing: {file_path}")
    
    if not os.path.exists(file_path):
        logging.warning(f"File not found {file_path}")
        return

    # Check if empty
    if os.path.getsize(file_path) == 0:
        logging.info(f"Skipping empty file: {file_path}")
        return

    try:
        with open(file_path, 'r', encoding='utf-8-sig') as f:
            data = yaml_rt.load(f)
    except Exception as e:
        logging.error(f"Error loading {file_path}: {e}")
        return

    if data is None:
        return

    update_tm_dict(data, file_path)
    
    # Save
    if not dry_run:
        dir_name = os.path.dirname(file_path)
        file_name = prefix + os.path.basename(file_path)
        out_path = os.path.join(dir_name, file_name)
        
        with open(out_path, 'w', encoding='utf-8') as f:
            yaml_rt.dump(data, f)
        logging.info(f"Saved: {out_path}")
    else:
        logging.info(f"Dry run: Would have saved {file_path}")
        
    # Recurse into children
    if 'children' in data and data['children']:
        dir_name = os.path.dirname(file_path)
        for child_ref in data['children']:
            if not isinstance(child_ref, dict):
                continue
            child_id = child_ref.get('REFID') or child_ref.get('ID')
            if not child_id:
                continue
            
            # Resolve file path
            child_path = None
            if child_id.endswith('.yaml'):
                child_path = os.path.join(dir_name, child_id)
            else:
                # Try directory-based path
                child_path = os.path.join(dir_name, child_id, child_id + ".yaml")
                if not os.path.exists(child_path):
                    # Try same directory
                    child_path = os.path.join(dir_name, child_id + ".yaml")
            
            if child_path and os.path.exists(child_path):
                process_file_recursive(child_path, prefix, processed, dry_run)

def main():
    parser = argparse.ArgumentParser(description="Normalize Threat Model YAML files to Schema 2")
    parser.add_argument("--rootTMYaml", required=True, help="Path to the root YAML file")
    parser.add_argument("--YAMLprefix", default="", help="Prefix for updated files (default: overwrite)")
    parser.add_argument("--dryRun", action="store_true", help="Do not save changes")
    args = parser.parse_args()
    
    process_file_recursive(args.rootTMYaml, args.YAMLprefix, dry_run=args.dryRun)

if __name__ == "__main__":
    main()
