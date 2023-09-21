#!/usr/bin/env python3

import os
from tokenize import String
import argparse
import time
from watchdog.observers import Observer
from watchdog.events import LoggingEventHandler, PatternMatchingEventHandler
import traceback
from mako.exceptions import RichTraceback
from mako.lookup import TemplateLookup
from mako.template import Template
import markdown
import importlib_resources

from r3threatmodeling import createThreatPlantUMLDiagrams, createSecObjTreePUMLDiagrams, createSecObjectivesPlantUML, report_generator

from .threatmodel_data import *
from markdown import Markdown
from .template_utils import *

from pathlib import Path
import shutil


def generateSingleTM(rootTMYaml, outputDir, assetDir, template, ancestorData=True, browserSync=False, public=False):
    print(f"FULL BUILD on {outputDir}")

    if assetDir:
        shutil.copytree(assetDir[0], outputDir, dirs_exist_ok=True)

    tmo = ThreatModel(rootTMYaml, public=public)
    tmID = tmo.id
    tmTitle = tmo.title

    report_generator.generate(tmo, template, ancestorData, outputDir, browserSync, None, assetDir)


    for tm in tmo.getDescendants() + [tmo]:
        asset_path = tm.assetDir()
        if os.path.isdir(asset_path):
            shutil.copytree(asset_path, outputDir, dirs_exist_ok=True)

    print(f"Generate plant uml diagrams")
    threatTree_outputDir = outputDir+'/img/threatTree'
    os.makedirs(threatTree_outputDir, exist_ok=True)
    createThreatPlantUMLDiagrams.generate(tmo, threatTree_outputDir)
    PUMLCommand = f"docker run --rm -v {os.path.realpath(threatTree_outputDir)}:/data plantuml/plantuml *.puml -svg -v"
    print(f" executing: {PUMLCommand}")
    os.system(PUMLCommand)
    

    secObjectives_outputDir = outputDir+'/img/secObjectives'
    os.makedirs(secObjectives_outputDir, exist_ok=True)
    createSecObjTreePUMLDiagrams.generate(tmo, secObjectives_outputDir)
    PUMLCommand = f"docker run --rm -v {os.path.realpath(secObjectives_outputDir)}:/data plantuml/plantuml *.puml -svg -v"
    print(f" executing: {PUMLCommand}")
    os.system(PUMLCommand)

    img_outputDir = outputDir+'/img'
    os.makedirs(img_outputDir, exist_ok=True)
    createSecObjectivesPlantUML.generate(tmo, img_outputDir)
    PUMLCommand = f"docker run --rm -v {os.path.realpath(img_outputDir)}:/data plantuml/plantuml *.puml -svg -v"
    print(f" executing: {PUMLCommand}")
    os.system(PUMLCommand)

    print("Generating PDF from html version")

    os.makedirs(  "build/scripts", exist_ok=True)
    PDFscript = importlib_resources.files('r3threatmodeling').joinpath('scripts/pdfScript.js')
    shutil.copy(PDFscript, 'build/scripts/pdfScript.js')

    PDF_command =f"docker run -it --init --cap-add=SYS_ADMIN  -v {os.path.realpath('build/scripts')}:/home/pptruser/scripts -v \
{os.path.realpath(outputDir)}/:/home/pptruser/{outputDir} --rm ghcr.io/puppeteer/puppeteer:latest node scripts/pdfScript.js \
file:///home/pptruser/{outputDir}/{tmID}.html {outputDir}/{tmID}.pdf"
    print(f"Executing command: {PDF_command}")
    os.system(PDF_command)

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
    "--public", action='store_true'
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

    CLI.add_argument(
    "--rewriteYAMLDev",  
    action='store_true',
    required=False
    )

    CLI.add_argument(
    "--formatYAML",  
    action='store_true',
    required=False
    )

    CLI.add_argument(
    "--assetDir",
    nargs="+", 
    required=False
    )

    CLI.add_argument('--ancestorData', action='store_true')
    CLI.add_argument('--no-ancestorData', dest='ancestorData', action='store_false')
    CLI.set_defaults(ancestorData=True)

    CLI.add_argument('--baseFileName', default=None, required=False)

    args = CLI.parse_args()
    outputDir = args.outputDir
    watchFiles = args.watchFiles


    template = args.template
    ancestorData = args.ancestorData
    browserSync = args.browserSync
    assetDir = args.assetDir
    rootTMYaml = args.rootTMYaml
    public = args.public
    generateSingleTM(rootTMYaml, outputDir, assetDir, template, ancestorData, browserSync, public = public)




if __name__ == "__main__":
    main()