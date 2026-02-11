#!/usr/bin/env python3

#from lib2to3.pygram import pattern_symbols
from pathvalidate import sanitize_filename
import os
from tokenize import String
import yaml
from ruamel.yaml import YAML, CommentedMap
import ruamel.yaml
from ruamel.yaml.comments import CommentedMap
from ruamel.yaml.compat import ordereddict

import sys
import argparse
import time
import logging
from watchdog.observers import Observer
from watchdog.events import LoggingEventHandler, PatternMatchingEventHandler
import traceback

from r3threatmodeling.threatmodel_data import Countermeasure, Threat, ThreatModel




def com_insert(self, pos, key, value, comment=None):
    #print('insert!')
    #sys.exit(1)
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


#getPos = lambda oDict, toFind, byKey=True: list(oDict.keys() if byKey else oDict.values()).index(toFind)

def getPos(oDict, toFind, byKey=True):
    return list(oDict.keys() if byKey else oDict.values()).index(toFind)

# add new methods


def updateThreatModelYaml(self):
    if 'schemaVersion' not in self.originDict:
        # insert after ID
        try:
            order = getPos(self.originDict, 'ID') + 1
            self.originDict.insert(order, 'schemaVersion', 2)
        except ValueError:
            # ID not found? shouldn't happen for a TM, but just in case
            self.originDict['schemaVersion'] = 2
    elif self.originDict['schemaVersion'] < 2:
        self.originDict['schemaVersion'] = 2

    # Remove unused root attributes
    unused_root = ['executiveSummaryText', 'jiraLink', 'status', 'diagram', 'references', 'lastReview']
    for attr in unused_root:
        if attr in self.originDict:
            self.originDict.pop(attr)

    if 'scope' in self.originDict and self.originDict['scope'] is not None:
        if 'diagram' in self.originDict['scope']:
            self.originDict['scope'].pop('diagram')
        if 'references' in self.originDict['scope']:
            self.originDict['scope'].pop('references')
        
        if 'securityObjectives' in self.originDict['scope'] and self.originDict['scope']['securityObjectives'] is not None:
             for obj in self.originDict['scope']['securityObjectives']:
                 if 'lowPriority' in obj:
                     obj.pop('lowPriority')

    # Rename ID to REFID in children
    if 'children' in self.originDict and self.originDict['children'] is not None:
        for i in range(len(self.originDict['children'])):
            if isinstance(self.originDict['children'][i], dict) and 'ID' in self.originDict['children'][i] and 'REFID' not in self.originDict['children'][i]:
                val = self.originDict['children'][i].pop('ID')
                self.originDict['children'][i]['REFID'] = val

    for child in self.children:
        if isinstance(child, ThreatModel):
            child.updateYaml()

    for threat in self.threats:
        threat.updateYaml()



def updateThreatYaml(self):
    ##refactor YAML

    if 'description' in self.originDict:
        # Move description to attack if attack is missing, otherwise just pop it
        if 'attack' not in self.originDict or not self.originDict['attack']:
             self.originDict['attack'] = self.originDict.pop('description')
        else:
             self.originDict.pop('description')

    unused_threat = [
        'WIP', 'toReview', 'Taxonomy group', 'generic', 'sensitivity',
        'lowPriority', 'guide', 'required', 'createTicket', 'pentestTestable'
    ]
    for attr in unused_threat:
        if attr in self.originDict:
            self.originDict.pop(attr)

    if 'impacts' in self.originDict:
        order = getPos(self.originDict, 'impacts')
        impactedSecObj = self.originDict['impacts']
        self.originDict.pop('impacts')
        self.originDict.insert(order, 'impactedSecObj', impactedSecObj)

    # Migrate IDs to REFIDs in lists of references
    for list_field in ['impactedSecObj', 'threatActors', 'countermeasures', 'assets']:
        if list_field in self.originDict and self.originDict[list_field] is not None:
            for i in range(len(self.originDict[list_field])):
                item = self.originDict[list_field][i]
                if isinstance(item, dict) and 'ID' in item and 'REFID' not in item:
                    # If it has more than just ID, it might be a definition (like in countermeasures)
                    # For now, let's only rename if it's clearly intended as a reference
                    # Actually the parser handles REFID in definitions too now
                    val = item.pop('ID')
                    item['REFID'] = val



    for countermeasure in self.countermeasures:
        countermeasure.updateYaml()



def updateCountermeasureYaml(self):
    #method to update the yaml when calling Threat.dumpRecursive()
    #adding a default value
    if 'operational' in self.originDict:
        if self.originDict['operational'] == True:
            if 'operator' not in self.originDict:
                order = getPos(self.originDict, 'operational') + 1
                self.originDict.insert(order, 'operator', self.operator)

    unused_cm = ['guide', 'required', 'createTicket', 'sensitivity']
    for attr in unused_cm:
        if attr in self.originDict:
            self.originDict.pop(attr)


CommentedMap.insert = com_insert
ThreatModel.updateYaml = updateThreatModelYaml
Threat.updateYaml = updateThreatYaml
Countermeasure.updateYaml = updateCountermeasureYaml


def normalizeandDumpYAML(threatModel, filePrefix="", recursive=True):
    print('normalize!')


    threatModel.updateYaml()
    threatModel.dumpRecursive(prefix=filePrefix, recursive=recursive)

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
        "--dryRun",  
        action='store_true',
        required=False
    )

    args = CLI.parse_args()
 
    tm = ThreatModel(args.rootTMYaml)

    # unmitigatedNoOperational = tm.getThreatsByFullyMitigatedAndOperational(False, False)

    # for  threat in unmitigatedNoOperational:
    #     threat.ticketLink = f"http://jira....?id={threat.id}"

    if(not args.dryRun):
        normalizeandDumpYAML(tm, args.YAMLprefix)

if __name__ == "__main__":
    main()