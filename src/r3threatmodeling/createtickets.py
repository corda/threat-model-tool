#!/usr/bin/env python3

from lib2to3.pygram import pattern_symbols
from pathvalidate import sanitize_filename
import os
from tokenize import String
import yaml
import sys
import argparse
import time
import logging
from watchdog.observers import Observer
from watchdog.events import LoggingEventHandler, PatternMatchingEventHandler
import traceback


from .r3threatmodeling import *


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

    unmitigatedNoOperational = tm.getThreatsByFullyMitigatedAndOperational(False, False)

    for  threat in unmitigatedNoOperational:
        threat.ticketLink = f"http://jira....?id={threat.id}"

    if(not args.dryRun):
        tm.dumpRecursive(prefix=args.YAMLprefix)

main()