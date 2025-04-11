#!/usr/bin/env python3

import os
import shutil  
import pathlib
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

from r3threatmodeling import fullBuildSingleTM
from .threatmodel_data import *
from markdown import Markdown
from .template_utils import *

from pathlib import Path
import shutil

def dir_path(path):
    if os.path.isdir(path):
        return path
    else:
        raise argparse.ArgumentTypeError(f"--TMDirectory:{path} is not a valid path")

def generateFromTMList(tm_list, outputDir, outFile , template = "index_tm_list", pdfArtifactLink=None):
    # template = "index_tm_list"
    try:
        mdTemplate = Template(
            filename =  os.path.join(os.path.dirname(__file__),
                'template/'+template+'.mako'),
                lookup=TemplateLookup(
                    directories=['.', 
                                os.path.join(os.path.dirname(__file__),'/template/'), "/"]
                                , output_encoding='utf-8', preprocessor=[lambda x: x.replace("\r\n", "\n")]
                ))
        
        outText = mdTemplate.render(tm_list=tm_list, mainLinks=[], outputDir=outputDir)
        outputFilename = outMDPath = os.path.join(outputDir, outFile)  
        with open(outputFilename, 'w') as f:
            print(f"OUTPUT: {f.name}") 
            f.write(outText)
    except:
        # print(mako_exceptions.text_error_template().render())
        traceback = RichTraceback()
        for (filename, lineno, function, line) in traceback.traceback:
            print("File %s, line %s, in %s" % (filename, lineno, function))
            print(line, "\n")
        print("%s: %s" % (str(traceback.error.__class__.__name__), traceback.error))  
    return

def main():
    CLI=argparse.ArgumentParser()

    CLI.add_argument(
    "--TMDirectory",
    default = ".",  
    type=dir_path,
    required=False
    )

    CLI.add_argument(
    "--templateSiteFolderSRC",
    type=dir_path,
    required=False
    )

    CLI.add_argument(
    "--templateSiteFolderDST",
    required=False
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

    CLI.add_argument(
    "--pdfHeaderNote",
    default="Private and confidential", 
    required=False
    )

    CLI.add_argument('--ancestorData', action='store_true')
    CLI.add_argument('--no-ancestorData', dest='ancestorData', action='store_false')
    CLI.set_defaults(ancestorData=True)

    CLI.add_argument('--baseFileName', default=None, required=False)

    CLI.add_argument("--generatePDF", action='store_true')
    CLI.add_argument("--pdfArtifactLink", required=False)

    CLI.add_argument("--visibility", default="full", choices=["full", "public"])

    CLI.add_argument('--MKDocsSiteDir',  required=False)
    CLI.add_argument('--MKDocsDir',  required=False)

    CLI.add_argument(
    "--fileName",
    default=None, 
    required=False
    )


    args = CLI.parse_args()
    outputDir = args.outputDir
    templateSiteFolderSRC = args.templateSiteFolderSRC
    templateSiteFolderInitFromModule = os.path.join(os.path.dirname(__file__), 'assets/MKDOCS_init/')
    templateSiteFolderDST = args.templateSiteFolderDST
    watchFiles = args.watchFiles

    MKDocsSiteDir = args.MKDocsSiteDir
    MKDocsDir = args.MKDocsDir


    template = args.template
    ancestorData = args.ancestorData
    browserSync = args.browserSync
    assetDir = args.assetDir
    generatePDF = args.generatePDF
    pdfHeaderNote = args.pdfHeaderNote
    pdfArtifactLink = args.pdfArtifactLink
    public = True if args.visibility == "public" else False
    fileName = args.fileName

    TMDir = args.TMDirectory

    os.makedirs(outputDir, exist_ok=True)
    
    if templateSiteFolderDST:
        os.makedirs(templateSiteFolderDST, exist_ok=True)
        shutil.copytree(templateSiteFolderInitFromModule, templateSiteFolderDST, dirs_exist_ok=True)

    if templateSiteFolderSRC and templateSiteFolderDST:
        shutil.copytree(templateSiteFolderSRC, templateSiteFolderDST, dirs_exist_ok=True)

    tm_list = [{'name':f.stem, 'path':str(f)} for f in pathlib.Path(TMDir).glob("*/*.yaml") if pathlib.Path(f).parent.name == pathlib.Path(f).stem]

    tm_list = []#{'name':f.stem, 'path':str(f)} 
    # for f in pathlib.Path(TMDir).glob("*/*.yaml"):
    for f in sorted(pathlib.Path(TMDir).glob("*/*.yaml"), key=lambda f: f.name):
      if pathlib.Path(f).parent.name == pathlib.Path(f).stem:
        #tm_list
        path = str(f)
        name = f.stem
        print(path)
        import yaml
        tm = yaml.safe_load(open(f))
        title = tm['title']
        version = tm['version']
        pdfname = f'{title} Threat Model-{version}.pdf'
        pdfname = re.sub('[^\w_.)(_-]', '_', pdfname)   # replace invalid chars with underscore
        
        tm_list.append({'name': name,'ID': tm['ID'], 'path': path, 'title': title, 'pdf':pdfname})

    print(tm_list)        



    for tm in tm_list:
        rootTMYaml = tm['path']
        TMoutputDir = outputDir 
        
        fullBuildSingleTM.generateSingleTM(open(rootTMYaml), TMoutputDir, assetDir, template, ancestorData, browserSync , generatePDF=generatePDF, pdfHeaderNote=pdfHeaderNote, public=public, fileName=fileName)

        # fullBuildSingleTM.generateSingleTM(open(rootTMYaml), TMoutputDir + "/full", assetDir, template, ancestorData, browserSync , generatePDF=generatePDF, pdfHeaderNote=pdfHeaderNote, public=False)

    if MKDocsSiteDir:

        os.makedirs(MKDocsSiteDir, exist_ok=True)
        os.makedirs(MKDocsDir, exist_ok=True)

        generateFromTMList(tm_list, MKDocsDir, outFile="mkdocs.yml", template="conf_MKDOCS")    
        generateFromTMList(tm_list, outputDir, outFile="index.md", template="index_MKDOCS", pdfArtifactLink=None)

        if pdfArtifactLink:
            #unzip
            pass

        oldwd = os.getcwd()
        os.chdir(MKDocsDir)
        os.system(f"mkdocs build --clean --config-file mkdocs.yml --site-dir={MKDocsSiteDir}")
        os.chdir(oldwd)




if __name__ == "__main__":
    main()
