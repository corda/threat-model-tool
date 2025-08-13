#!/usr/bin/env python3

import os
from tokenize import String
import argparse
import time
from watchdog.observers import Observer
from watchdog.events import LoggingEventHandler, PatternMatchingEventHandler
import traceback
import re
## Mako imports removed after migration to pure Python renderers
## from mako.exceptions import RichTraceback
## from mako.lookup import TemplateLookup
## from mako.template import Template
import markdown

from .threatmodel_data import *
from markdown import Markdown
from .template.template_utils import *
from .template.renderers import render_template_by_name

from pathlib import Path
import shutil

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

"""Report generation utilities."""


def prepare_output_directory(outputDir, assetDir = None):
    os.makedirs(outputDir, exist_ok=True)
    # Assets removed; keep optional external assets if explicitly provided and exist
    if assetDir:
        for asset in assetDir:
            asset_path = Path(asset)
            if asset_path.exists():
                shutil.copytree(asset_path, outputDir, dirs_exist_ok=True)


def generate(tmo, template, ancestorData, outputDir, browserSync, baseFileName, assetDir, public=False, baseHeaderLevel: int = 1 ):

    if baseFileName is None:
        baseFileName = tmo._id

    mdOutFileName = baseFileName + ".md"
    htmlOutFileName = baseFileName + ".html"
    try:
        ctx = {}
        mdReport = render_template_by_name(template, tmo, ancestorData, ctx=ctx, header_level=baseHeaderLevel)
    except Exception as e:
        print(f"Template rendering error (Python renderer) for template {template}: {e}")
        traceback.print_exc()
        return

    mdReport = createTableOfContent(mdReport)

    mdReport = createRFIs(mdReport)

    # No diagram specific post-processing required


    postProcessTemplateFile(outputDir, browserSync, mdOutFileName, htmlOutFileName, mdReport, assetDir)

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
    "--versionsFilter", 
    default = None,
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
    CLI.add_argument('--baseHeaderLevel', type=int, default=1, required=False, help='Base markdown header level for top-level sections (Python renderer)')

    args = CLI.parse_args()
    # TMIDs = args.TMID
    outputDir = args.outputDir
    # browserSync = args.browserSync
    # rootTMYaml = args.rootTMYaml
    watchFiles = args.watchFiles
    # template = args.template
    # ancestorData = args.ancestorData
    # baseFileName = args.baseFileName

    prepare_output_directory(args.outputDir, args.assetDir)
    
    
    #First call, when run Generates the files
    processMultipleTMIDs(args)



    if watchFiles is not None:
        print (" watching Files ")
        # logging.basicConfig(level=logging.INFO,
        #                         format='%(asctime)s - %(message)s',
        #                         datefmt='%Y-%m-%d %H:%M:%S')
        # event_handler = LoggingEventHandler()
        observer = Observer()
        handler= make_handler(watchFiles, processMultipleTMIDs, args)
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



def processMultipleTMIDs(args):

    rootTMYamlFile = args.rootTMYaml
    TMIDs = args.TMID
    public =  args.public

    tmoRoot = ThreatModel(rootTMYamlFile, public=public, versionsFilterStr=args.versionsFilter)

    #Default value when --TMID is omitted in args
    if TMIDs == None:
        TMIDs = [tmoRoot.id]
 
    for tmid in TMIDs:
        processSingleTMID(tmoRoot, tmid, args)

    if args.rewriteYAMLDev:
        tmoRoot.dumpRecursive(prefix="dev_")

    if args.formatYAML:
        tmoRoot.dumpRecursive()
        


def processSingleTMID(tmoRoot, TMID, args):

    TMIDs = args.TMID
    outputDir = args.outputDir
    browserSync = args.browserSync
    watchFiles = args.watchFiles
    template = args.template
    ancestorData = args.ancestorData
    baseFileName = args.baseFileName
    rewriteYAMLDev = args.rewriteYAMLDev
    assetDir = args.assetDir
    public=args.public



    rootID = TMID #.rsplit('.',1)[0]
    if tmoRoot._id == rootID:
        tmo = tmoRoot
    else:
        raise Exception('parameter root id: '+ rootID +' not recognized, should be : '+tmoRoot._id)

        
    for idPathPart in TMID.split('.')[1:]:
        tmo = tmo.getChildrenTMbyID(idPathPart)
        

    generate(tmo, template, ancestorData, outputDir, browserSync, baseFileName, assetDir, public, baseHeaderLevel=args.baseHeaderLevel )
    return

def postProcessTemplateFile(outputDir, browserSync, mdOutFileName, htmlOutFileName, mdReport, assetDir):
    if not assetDir:
        assetDir = 'assets'

    htmlReport = markdown.markdown(mdReport, extensions=['md_in_html', 'attr_list'])
    baseHTML = """<!DOCTYPE html>
        <html>
        <head>
        <meta charset=\"utf-8\" />
        <link rel="stylesheet" href="css/tm.css">
        </head>
        <body>%BODY%</body>
        </html>
        """
    htmlReport = baseHTML.replace("%BODY%", htmlReport)

    if browserSync:
        htmlReport=htmlReport.replace("</body>","""
            <script id="__bs_script__">//<![CDATA[
        document.write("<script async src='http://HOST:3000/browser-sync/browser-sync-client.js?v=2.27.10'></script>".replace("HOST", location.hostname));//]]></script>
    </body> """)
        
    # (Diagram scripting removed)


    outMDPath = os.path.join(outputDir, mdOutFileName)
    print ("output MD file:" + outMDPath)

    outHTMLPath = os.path.join(outputDir, htmlOutFileName)
    print ("output HTML file:" + outHTMLPath)

    with open(outHTMLPath, 'w') as outFile:
        outFile.write(htmlReport)

    with open(outMDPath, 'w') as outFile:
        outFile.write(mdReport)

#Credits to https://github.com/exhesham/python-markdown-index-generator/blob/master/markdown_toc.py
def createTableOfContent(mdData):
    toc = ""
    lines = mdData.split('\n')
    for line in lines:
        if SKIP_TOC not in line:
            if re.match(r'^#+ ', line):
                title = re.sub('#','',line).strip()
                hash = createTitleAnchorHash(title)
                manipulated_line = '**[%s](#%s)**' % (title, hash)
                tabs = re.sub('#','  ',line.strip()[:line.strip().index(' ')+1])
                toc += (tabs+ '* ' + manipulated_line + "\n")
    return mdData.replace("__TOC_PLACEHOLDER__", toc)

def createRFIs(mdData):
    rfilist = []
    newstring = ''
    start = 0
    counter = 1
    
    for m in re.finditer(r"\(RFI[\s:]*(.*)\)", mdData):
        
        rfi = m.group(1) if m.group(1) else 'Please complete'
        rfilist.append(rfi)
        end, newstart = m.span()
        newstring += mdData[start:end]
        
        # doesn't cope with markdown embedded in html
        # rep = f'[^{counter}] '
        rep = f'<sup><a id="backtorfi{counter}" href="#rfi{counter}">[RFI:{counter}]</a></sup> '

        newstring += rep
        start = newstart
        counter += 1
    newstring += mdData[start:]

    #rfi = '\n'.join( [ f'[^{i+1}]: {r}' for i,r in enumerate(rfilist) ] )

    rfil = '\n'.join( [ f'<li id="rfi{i+1}">{r} <a href="#backtorfi{i+1}">&#8617</a></li>' for i,r in enumerate(rfilist) ] )

    rfi = '<ol>'+rfil+'</ol>'

    return newstring.replace("__RFI_PLACEHOLDER__", rfi)



if __name__ == "__main__":
    main()