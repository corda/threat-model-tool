#!/usr/bin/env python3

# from lib2to3.pygram import pattern_symbols
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

from mako.exceptions import RichTraceback
from mako.lookup import TemplateLookup
from mako.template import Template
import markdown

from .threatmodel_data import *
from markdown import Markdown
from .template_utils import *


def generate(tmo, outputDir, template="secObjTreePlantUMLDiagram"):
    try:
        mdTemplate = Template(
            filename =  os.path.join(os.path.dirname(__file__),
                'template/'+template+'.mako'),
                lookup=TemplateLookup(
                    directories=['.', 
                                os.path.join(os.path.dirname(__file__),'/template/'), "/"]
                                , output_encoding='utf-8', preprocessor=[lambda x: x.replace("\r\n", "\n")]
                ))
        
        for secObj in tmo.securityObjectives:
            text = mdTemplate.render(secObj=secObj)
            mermaidFileName = outMDPath = os.path.join(outputDir, secObj._id + ".puml")   
            with open(mermaidFileName, 'w') as f:
                f.write(text)
        for child in tmo.getDescendantsTM():
            # parentOutputDir = os.path.join(base_outputDir, tmo._id)
            generate(child, outputDir, template)      
    except:
        # print(mako_exceptions.text_error_template().render())
        traceback = RichTraceback()
        for (filename, lineno, function, line) in traceback.traceback:
            print("File %s, line %s, in %s" % (filename, lineno, function))
            print(line, "\n")
        print("%s: %s" % (str(traceback.error.__class__.__name__), traceback.error))

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

    template = "secObjTreePlantUMLDiagram"
 
    tmo = ThreatModel(args.rootTMYaml)
    outputDir = args.outputDir

    generate(outputDir, template)

    return 

if __name__ == "__main__":
    main()