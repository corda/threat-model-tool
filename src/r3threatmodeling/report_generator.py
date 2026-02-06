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
import hashlib, base64

from .threatmodel_data import *
from markdown import Markdown
from .template.template_utils import *
from .template.renderers import render_template_by_name

from pathlib import Path
import shutil


# def linkhash(title):
#     # Create a SHA-256 hash of the title
#     sha256_hash = hashlib.sha256(title.encode('utf-8')).digest()
#     # Encode the hash in base64
#     b64_hash = base64.b64encode(sha256_hash).decode('utf-8')
#     # Return the first 10 characters for brevity
#     return b64_hash[:10]

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


def generate(tmo, template, ancestorData, outputDir, browserSync, baseFileName, assetDir, public=False, baseHeaderLevel: int = 1, mainTitle=None):

    if baseFileName is None:
        baseFileName = tmo._id

    mdOutFileName = baseFileName + ".md"
    htmlOutFileName = baseFileName + ".html"
    
    ## Context default values
    ctx = {
        'processToc': True,
        'process_prepost_md': True,
        'process_heading_numbering': True,
        'mainTitle': mainTitle
    }

    assetDir0 = os.getcwd() + os.sep + tmo.fileName.replace(tmo.fileName.split('/')[-1],'assets')

    try:
        if Path(f"{assetDir0}/markdown_sections_1").exists():
            baseHeaderLevel = baseHeaderLevel + 1
        
        mdReport = render_template_by_name(template, tmo, ancestorData, ctx=ctx, header_level=baseHeaderLevel)
    except Exception as e:
        print(f"Template rendering error (Python renderer) for template {template}: {e}")
        traceback.print_exc()
        return
    
    # if not "__TOC_PLACEHOLDER__" in mdReport:
    #     processToc = False
    # else:
    #     processToc = True

    # Post-process the generated markdown report
    # Include md from <main folder>/assets/markdown_sections_1/pre_NN_*.md on top of the document
    # Include md from <main folder>/assets/markdown_sections_1/post_NN_*.md at the end of the document

    if Path(f"{assetDir0}/markdown_sections_1").exists() and ctx.get('process_prepost_md', True):

        #detele previoud __TOC_PLACEHOLDER__ from template rendering
        mdReport = mdReport.replace("__TOC_PLACEHOLDER__", "")
    
        # Remove any stray "#Table of content" heading line (case-insensitive, with or without space after '#')
        mdReport = re.sub(r'(?im)^\s*#\s*table\s+of\s+content\s*\r?\n?', '', mdReport)

        # Collapse repeated pagebreak divs with no intervening content into a single pagebreak.
        # This targets sequences like: <div class="pagebreak"></div>\n\n<div class="pagebreak"></div>
        try:
            pagebreak_seq_re = re.compile(r'(?:<div\s+[^>]*class=["\']pagebreak["\'][^>]*>\s*</div>\s*){2,}', re.IGNORECASE)
            mdReport = pagebreak_seq_re.sub('<div class="pagebreak"></div>\n', mdReport)
        except Exception:
            traceback.print_exc()


        pre_md_files = sorted(Path(f"{assetDir0}/markdown_sections_1").glob("pre_??_*.md"), reverse=True)
        post_md_files = sorted(Path(f"{assetDir0}/markdown_sections_1").glob("post_??_*.md"), reverse=False)

        for md_file in pre_md_files:
            with open(md_file, "r") as f:
                mdReport = f.read() + "\n" + mdReport

        for md_file in post_md_files:
            with open(md_file, "r") as f:
                mdReport = mdReport + "\n" + f.read()
        

    # Add numbering to all titles using the HeadingNumberer if enabled
    # We'll walk the markdown line-by-line, skip fenced code blocks, and
    # prefix headings with hierarchical numbers when HeadingNumberer is enabled.
    try:

        if is_heading_numbering_enabled():
            new_lines = []
            in_fence = False
            number_started = False
            fence_pattern = re.compile(r'^\s*(```|~~~)')
            # match headings like '# Title' or '## Title'
            heading_pattern = re.compile(r'^(?P<hashes>#{1,6})\s+(?P<title>.*)')

            lineNum = 0
            previousHeader =""
            for line in mdReport.splitlines():
                lineNum += 1
                # always detect fenced code block start/end (so we don't mis-detect placeholders inside code)
                if fence_pattern.match(line):
                    in_fence = not in_fence
                    new_lines.append(line)
                    continue

                # If we haven't reached the TOC placeholder yet, copy lines unchanged
                if not number_started:
                    if "__TOC_PLACEHOLDER__" in line:
                        # start numbering from here; reset counters so TOC headings start at 1
                        number_started = True
                        # reset_heading_numbers()
                    new_lines.append(line)
                    continue

                if in_fence:
                    new_lines.append(line)
                    continue

                m = heading_pattern.match(line)
                if m:
                    level = len(m.group('hashes'))
                    title = m.group('title').strip()

                    # if title already starts with a numbering like '1.' or '1.2 '
                    if re.match(r'^\d+(?:[\.\d]*\s*-?\s*)', title):
                        # leave as-is
                        new_lines.append(line)
                    else:
                        try:
                            # get next number for this level
                            num = HeadingNumberer().get_number(level)
                        except ValueError:
                            # invalid heading level (e.g., skipping levels)
                            print(f"ERROR: after header {previousHeader}: Invalid heading level {level} for line number {lineNum}: {line}")
                            exit(-2)
                        if num:
                            numbered_title = f"{num} {title}"
                        else:
                            numbered_title = title
                        new_lines.append(f"{m.group('hashes')} {numbered_title}")
                    previousHeader = line    
                else:
                    new_lines.append(line)

            mdReport = '\n'.join(new_lines)
    except Exception:
        # numbering should not break report generation; log and continue
        traceback.print_exc()
    if ctx.get('process_toc', True):
        mdReport = createTableOfContent(mdReport)

    # mdReport = createRFIs(mdReport)

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

    htmlReport = markdown.markdown(mdReport, 
            extensions=['md_in_html', "attr_list",
            "pymdownx.highlight",
            "pymdownx.superfences"])

    baseHTML = """<!DOCTYPE html>
        <html>
        <head>
        <meta charset=\"utf-8\" />
        <link rel="stylesheet" href="css/tm.css">
        <link rel="stylesheet" href="css/github.min.css">
        <script src="js/highlight.min.js"></script>
        <script>hljs.highlightAll();</script>
        </head>
        <body>%BODY%</body>
        </html>
        """
    htmlReport = baseHTML.replace("%BODY%", htmlReport)

    if browserSync and False: # disabled till tested and fixed
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

def transform_named_anchor_md(text):
    m = re.search(
        r"(?s)^(?P<text>.*?)(?:\s*<a\s+(?:name|id)\s*=\s*['\"](?P<name>[^'\"]+)['\"][^>]*>\s*</a>\s*)$",
        text,
    )
    if m:
        t = m.group('text').rstrip()
        name = m.group('name')
        return f"[{t}](#{name}){{.tocLink}}"
    return text

#Credits to https://github.com/exhesham/python-markdown-index-generator/blob/master/markdown_toc.py
def createTableOfContent(mdData, levelLimit=4):
    """
    Generate a table of contents and insert anchors into headings.
    Rebuilds the document line-by-line to avoid replacement issues.
    """
    toc = ""
    new_lines = []
    toc_inserted = False
    
    lines = mdData.split('\n')
    for line in lines:
        # Check if this line is the TOC placeholder
        if "__TOC_PLACEHOLDER__" in line:
            # We'll insert the TOC here after processing all headings
            new_lines.append("__TOC_PLACEHOLDER__")
            continue
            
        # if SKIP_TOC not in line or True:  # SKIP_TOC removed to always process all lines
        if re.match(r'^#+ ', line) and not  SKIP_TOC in line:
            title = re.sub('#', '', line).strip()
            
            # Check if header already has an anchor
            anchor_pat = re.compile(r"<a\s+(?:name|id)\s*=\s*['\"][^'\"]+['\"][^>]*>\s*</a>", re.IGNORECASE)
            
            if not anchor_pat.search(line):
                # Add anchor to this heading
                anchor_name = createTitleAnchorHash(title)
                anchor_html = f" <a name='{anchor_name}' class='tocLink'></a>"
                modified_line = line + anchor_html
                title = title + anchor_html
            else:
                modified_line = line
            
            # Add the (possibly modified) line to output
            new_lines.append(modified_line)
            
            # Transform title for TOC entry
            title = transform_named_anchor_md(title)
            
            level = line.count('#')
            hash = createTitleAnchorHash(title)
            
            # Build TOC entry based on level
            if level < 2:
                md_toc_entry_with_link = '**%s**' % (title)
            elif level == 2:
                md_toc_entry_with_link = '***%s***' % (title)
            elif level <= levelLimit:
                md_toc_entry_with_link = '%s' % (title)
            else:
                continue
            
            tabs = re.sub('#', '&nbsp;&nbsp;', line.strip()[:line.strip().index(' ')+1])
            toc += (tabs + ' ' + md_toc_entry_with_link + "\n\n")
            # else:
            #     # Not a heading, just pass through
            #     new_lines.append(line)
        else:
            new_lines.append(line)
    
    # Reconstruct document with anchors added
    mdData = '\n'.join(new_lines)
    
    # Now replace the TOC placeholder with actual TOC
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