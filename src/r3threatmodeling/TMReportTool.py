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


def make_handler(files, func, *args):
    class Handler(PatternMatchingEventHandler):
        def on_modified(self, event):
            print('Modified: {}'.format(event.src_path))
            # with open(file_name) as f:
            #     code = f.read()
            try:
             func(*args)
            except Exception as e:
             #   print ("Error:" + str(e)) 
                traceback.print_exc()
    patterns = []
    for file in files:
        patterns.append(os.path.abspath(file.name))

    return Handler(patterns=patterns) 


def main():
    CLI=argparse.ArgumentParser()

    CLI.add_argument(
    "--TMID",  
    required=False,
    nargs='+'
    )

    CLI.add_argument(
    "--outputDir", 
    default = "build",
    required=False
    )

    CLI.add_argument(
    "--browserSync", action='store_true'
    )

    CLI.add_argument(
    "--rootTMYaml",
    default = None,
    required=True,
    type=open
    )

    CLI.add_argument(
    "--template",
    default = "TM_template",
    required=False
    )

    CLI.add_argument(
    "--watchFiles",  
    nargs="+",  
    type=open,
    required=False
    )

    CLI.add_argument('--ancestorData', action='store_true')
    CLI.add_argument('--no-ancestorData', dest='ancestorData', action='store_false')
    CLI.set_defaults(ancestorData=True)

    CLI.add_argument('--baseFileName', default=None, required=False)

    args = CLI.parse_args()
    TMIDs = args.TMID
    outputDir = args.outputDir
    browserSync = args.browserSync
    rootTMYaml = args.rootTMYaml
    watchFiles = args.watchFiles
    template = args.template
    ancestorData = args.ancestorData
    baseFileName = args.baseFileName

    os.makedirs(outputDir, exist_ok=True)
    
    #First call, when run Generates the files
    processCommandLine(TMIDs, outputDir, browserSync, rootTMYaml, template, ancestorData, baseFileName)

    if watchFiles is not None:
        print (" watching Files ")
        # logging.basicConfig(level=logging.INFO,
        #                         format='%(asctime)s - %(message)s',
        #                         datefmt='%Y-%m-%d %H:%M:%S')
        # event_handler = LoggingEventHandler()
        observer = Observer()
        handler= make_handler(watchFiles, processCommandLine, TMIDs, outputDir, browserSync, rootTMYaml, template, ancestorData, baseFileName)
        observer.schedule(
            handler,
             os.getcwd(), recursive=True)
        observer.start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            observer.stop()
        observer.join()


def processCommandLine(TMIDs, outputDir, browserSync, rootTMYaml, template, ancestorData, baseFileName):
    # if rootTMYaml == None:
    #     return processSeparatedReports(TMID, outputDir, browserSync, template)
    # else:
    processMultipleTMIDs(TMIDs, outputDir, browserSync, rootTMYaml, template, ancestorData, baseFileName)
        # return -2



# def processSeparatedReports(TMID, outputDir, browserSync):
#     for tmid in TMID:
#         print ("processing Threat Model ID  " + tmid.name)
#         if not tmid.name.lower().endswith('.yaml'):
#             print("input file needs to be .yaml")
#             exit -2
     
#         mdOutFileName = ntpath.basename(tmid.name)[:-5] + ".md"
#         htmlOutFileName = ntpath.basename(tmid.name)[:-5] + ".html"

#         try:
#             tmDict = parseYamlThreatModelAndParentsToDict(tmid)
#             mdReport = createMarkdownReport(tmDict)
#             mdReport = createTableOfContent(mdReport)
#         except:
#             raise
#         postProcessTemplateFile(outputDir, browserSync, mdOutFileName, htmlOutFileName, mdReport)






main()


