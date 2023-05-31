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

    CLI.add_argument(
    "--rewriteYAMLDev",  
    action='store_true',
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
    rewriteYAMLDev = args.rewriteYAMLDev

    os.makedirs(outputDir, exist_ok=True)
    
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

    # print ("processRootTMYaml file: " + rootTMYamlFile.name)
    # if not rootTMYamlFile.name.lower().endswith('.yaml'):
    #     raise ValueError("input file "+ rootTMYamlFile.name + "needs to be .yaml")
    rootTMYamlFile = args.rootTMYaml
    TMIDs = args.TMID

    tmoRoot = ThreatModel(rootTMYamlFile)
 

    for tmid in TMIDs:
        processSingleTMID(tmoRoot, tmid, args)


def processSingleTMID(tmoRoot, TMID, args):

    TMIDs = args.TMID
    outputDir = args.outputDir
    browserSync = args.browserSync
    watchFiles = args.watchFiles
    template = args.template
    ancestorData = args.ancestorData
    baseFileName = args.baseFileName
    rewriteYAMLDev = args.rewriteYAMLDev

    if baseFileName is None:
        baseFileName = TMID

    mdOutFileName = baseFileName + ".md"
    htmlOutFileName = baseFileName + ".html"

    rootID = TMID.split('.')[0]
    if tmoRoot._id == rootID:
        tmo = tmoRoot
    else:
        raise Exception('root id: '+ rootID +' not recognized, should be : '+tmoRoot._id)

        
    for idPathPart in TMID.split('.')[1:]:
        tmo = tmo.getChildrenTMbyID(idPathPart)
        

    try:
        mdTemplate = Template(
        filename=  os.path.join(os.path.dirname(__file__),
            'template/'+template+'.mako'),
            lookup=TemplateLookup(
                directories=['.', 
                             os.path.join(os.path.dirname(__file__),'/template/'), "/"]
                            , output_encoding='utf-8', preprocessor=[lambda x: x.replace("\r\n", "\n")]
            ))
        # ancestorData = True
        mdReport = mdTemplate.render(tmo=tmo, ancestorData=ancestorData)
    except:
        # print(mako_exceptions.text_error_template().render())
        traceback = RichTraceback()
        for (filename, lineno, function, line) in traceback.traceback:
            print("File %s, line %s, in %s" % (filename, lineno, function))
            print(line, "\n")
        print("%s: %s" % (str(traceback.error.__class__.__name__), traceback.error))
        return 
        # raise BaseException("Template rendering error")

    mdReport = createTableOfContent(mdReport)

    mdReport = createRFIs(mdReport)


    postProcessTemplateFile(outputDir, browserSync, mdOutFileName, htmlOutFileName, mdReport)
    return

def postProcessTemplateFile(outputDir, browserSync, mdOutFileName, htmlOutFileName, mdReport):
    mermaidHtmlTags = mdReport.replace(#FIX mermaid diagrams for html
                "<!-- mermaid start. Do not delete this comment-->\n```mermaid", "<div class=mermaid>").replace("```\n<!-- mermaid end. comment needed to it covert to HTML-->","</div>")

    htmlReport = markdown.markdown(mermaidHtmlTags, extensions=['md_in_html'])
        
    baseHTML = """<!DOCTYPE html>
        <html>
        <head>
        <style>
        @media print {
            .pagebreak {
                clear: both;
                min-height: 1px;
                page-break-after: always;
            }
        }</style>
        <link rel="stylesheet" href="css/tm.css">
        </head>
        <body>%BODY%</body>
        </html>
        """
    htmlReport = baseHTML.replace("%BODY%", htmlReport)

    if browserSync:
        htmlReport=htmlReport.replace("</body>","""
            <script id="__bs_script__">//<![CDATA[
        document.write("<script async src='http://HOST:3000/browser-sync/browser-sync-client.js?v=2.27.10'><\/script>".replace("HOST", location.hostname));//]]></script>
    </body> """)
        
    mermaid_script = """
<script src="https://cdn.jsdelivr.net/npm/mermaid/dist/mermaid.min.js"></script>
<script>mermaid.initialize({startOnLoad:true});
</script>
"""
    htmlReport=htmlReport.replace("</body>",    mermaid_script + "</body>")    


    outMDPath = os.path.join(outputDir, mdOutFileName)
    print ("output MD file:" + outMDPath)

    outHTMLPath = os.path.join(outputDir, htmlOutFileName)
    print ("output HTML file:" + outHTMLPath)

    with open(outHTMLPath, 'w') as outFile:
        outFile.write(htmlReport)

    with open(outMDPath, 'w') as outFile:
        outFile.write(mdReport)






main()


