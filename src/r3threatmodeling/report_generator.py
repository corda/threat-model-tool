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

from .threatmodel_data import *
from markdown import Markdown
from .template_utils import *

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

PRE_MERMAID = "<!-- mermaid start. Do not delete this comment-->\n```mermaid"
AFTER_MERMAID = "```\n<!-- mermaid end. comment needed to it covert to HTML-->"


def prepare_output_directory(outputDir, assetDir = None):

  os.makedirs(outputDir, exist_ok=True)

  if not assetDir:
    assetDir = []    

  # copy the basic assets first that are defined by this tool
  assetDir.insert(0, Path(__file__).parent / "assets")

  # copy everything from assets into destination 
  for asset in assetDir:
    shutil.copytree(asset, outputDir, dirs_exist_ok = True)

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

    tmoRoot = ThreatModel(rootTMYamlFile)

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

    # mdReport = "\n".join(process_mermaidInclude(mdReport.splitlines(), assetDir[1]))


    postProcessTemplateFile(outputDir, browserSync, mdOutFileName, htmlOutFileName, mdReport, assetDir)
    return

def postProcessTemplateFile(outputDir, browserSync, mdOutFileName, htmlOutFileName, mdReport, assetDir):
    if not assetDir:
        assetDir = 'assets'
    mermaidHtmlTags = mdReport.replace(#FIX mermaid diagrams for html
                PRE_MERMAID, "<div class=mermaid>").replace(AFTER_MERMAID,"</div>")

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
<script>mermaid.initialize({startOnLoad:true, securityLevel: 'loose'});
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


INC_SYNTAX = re.compile(r"{mermaid!\s*(.+?)\s*!((\blines\b)=([0-9 -]+))?\}")
HEADING_SYNTAX = re.compile("^#+")



def process_mermaidInclude(lines, base_path, encoding = "utf-8"):
    done = False
    bonusHeading = ""
    while not done:
        for loc, line in enumerate(lines):
            m = INC_SYNTAX.search(line)

            while m:
                filename = m.group(1)
                filename = os.path.expanduser(filename)
                if not os.path.isabs(filename):
                    filename = os.path.normpath(
                        os.path.join(base_path.__str__(), filename)
                    )
                try:
                    with open(filename, "r", encoding=encoding) as r:
                        original_text = process_mermaidInclude(r.readlines(), base_path, encoding)

                except Exception as e:
                    # if not self.throwException:
                    print(
                        "Warning: could not find file {}. Ignoring "
                        " try using --assetDir option \n"
                        "include statement. Error: {}".format(filename, e)
                    )
                    lines[loc] = INC_SYNTAX.sub("", line)
                    break

                text = original_text

                if len(text) == 0:
                    text.append("")

                text.append(AFTER_MERMAID)
                text.insert(0, PRE_MERMAID)
                del lines[loc]
                lines[loc:loc] =text 
                m = INC_SYNTAX.search("")

        else:
            done = True
    return lines

if __name__ == "__main__":
    main()