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

    template = "threatPlantUMLDiagram"
 
    tmo = ThreatModel(args.rootTMYaml)
    outputDir = args.outputDir


    try:
        mdTemplate = Template(
            filename =  os.path.join(os.path.dirname(__file__),
                'template/'+template+'.mako'),
                lookup=TemplateLookup(
                    directories=['.', 
                                os.path.join(os.path.dirname(__file__),'/template/'), "/"]
                                , output_encoding='utf-8', preprocessor=[lambda x: x.replace("\r\n", "\n")]
                ))
        
        for threat in tmo.getAllDown("threats"):
            mermaidText = mdTemplate.render(threat=threat)
            mermaidFileName = outMDPath = os.path.join(outputDir, threat._id + ".mmd")   
            with open(mermaidFileName, 'w') as f:
                f.write(mermaidText)
    except:
        # print(mako_exceptions.text_error_template().render())
        traceback = RichTraceback()
        for (filename, lineno, function, line) in traceback.traceback:
            print("File %s, line %s, in %s" % (filename, lineno, function))
            print(line, "\n")
        print("%s: %s" % (str(traceback.error.__class__.__name__), traceback.error))
        return 

if __name__ == "__main__":
    main()