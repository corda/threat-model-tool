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
    for childrenTM in self.childrenTM:
        childrenTM.updateYaml()

    for threat in self.threats:
        threat.updateYaml()



def updateThreatYaml(self):
    ##refactor YAML

    # rename a yaml field
    # WARNING: as this is a commented map we may loss the comments 

    if 'impacts' in self.originDict:
        order = getPos(self.originDict, 'impacts')
        impactedSecObj = self.originDict['impacts']
        self.originDict.pop('impacts')
        self.originDict.insert(order, 'impactedSecObj', impactedSecObj)


    if 'impact' in self.originDict:
        impact = self.originDict['impact']
        self.originDict.pop('impact')
        order = 2
        if 'impactedSecObj' in self.originDict:
            order = getPos(self.originDict, 'impactedSecObj')
        self.originDict.insert(order, 'impactDesc', impact)

    if 'assets' in self.originDict:
        # self.originDict['assets'].append({'REFID': 't4st'})
        if self.originDict['assets'] != None:
            for i in range(len(self.originDict['assets'])):
            # for asset in self.originDict['assets']:
                if not "REFID" in self.originDict['assets'][i]:
                    self.originDict['assets'][i] = {'REFID':  self.originDict['assets'][i]['ID']}
                # self.originDict['assets'].insert(1, 'REFID', asset['ID'])
                # self.originDict['assets'].pop(asset['ID'])



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


CommentedMap.insert = com_insert
ThreatModel.updateYaml = updateThreatModelYaml
Threat.updateYaml = updateThreatYaml
Countermeasure.updateYaml = updateCountermeasureYaml


def normalizeandDumpYAML(threatModel, filePrefix=""):
    print('normalize!')


    threatModel.updateYaml()
    threatModel.dumpRecursive(prefix=filePrefix)

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