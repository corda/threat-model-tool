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

def generateFromTMList(tm_list, outputDir, outFile , pdfArtifactLink=None):
    """Generate a simple Markdown index for a list of threat models (no templates)."""
    lines = ["# Threat Models Index", ""]
    if pdfArtifactLink:
        lines.append(f"PDF Artifact: {pdfArtifactLink}\n")
    for tm in tm_list:
        tm_id = getattr(tm, '_id', 'UNKNOWN')
        title = getattr(tm, 'title', tm_id)
        lines.append(f"* [{title}]({tm_id}/{tm_id}.html)")
    outText = "\n".join(lines) + "\n"
    os.makedirs(outputDir, exist_ok=True)
    outputFilename = os.path.join(outputDir, outFile)
    with open(outputFilename, 'w') as f:
        print(f"OUTPUT: {f.name}")
        f.write(outText)
    return


def generate_mkdocs_config(tm_list, outputDir, filename="mkdocs.yml"):
    """Generate a MkDocs configuration file approximating the legacy Mako template.

    Sections included (mirroring original template intent):
      - site_name
      - use_directory_urls (set false as in template)
      - nav (Home + one entry per TM -> <ID>/index.md)
      - theme (readthedocs)
      - markdown_extensions (toc, md_in_html, attr_list)
      - plugins (left mostly empty / placeholder for future enablement)
      - extra_css / extra_javascript
    """
    def yaml_quote(s: str) -> str:
        if s is None:
            return '""'
        if any(c in s for c in [':', '{', '}', '[', ']', ',', '&', '*', '#', '!', '|', '>', "'", '"', '%', '@', '`']):
            return '"' + s.replace('"', '\\"') + '"'
        return s

    lines = [
        "site_name: Threat Models",
        "docs_dir: docs",
        "use_directory_urls: false",
        "nav:",
        "  - Home: index.md",
    ]

    # Stable ordering: by title (fallback ID)
    for tm in sorted(tm_list, key=lambda x: (x.get('title') or x.get('ID') or x.get('name') or '')):
        title = tm.get('title') or tm.get('ID') or tm.get('name') or 'UNKNOWN'
        tm_id = tm.get('ID') or tm.get('name') or 'UNKNOWN'
        lines.append(f"  - {yaml_quote(title)}: {tm_id}/index.md")

    # Theme (basic built-in theme to avoid dependency issues)
    lines += [
        "",
        "theme:",
        "  name: readthedocs",
    ]

    # Markdown extensions
    lines += [
        "markdown_extensions:",
        "  - toc:",
        "      baselevel: 1",
        "      toc_depth: 5",
        "  - md_in_html",
        "  - attr_list",
    ]

    # Plugins (keep minimal; user can extend later) - search is default if omitted; we keep placeholder
    lines += [
        "plugins:",
        "  - search",
    ]

    # Static assets
    lines += [
        "extra_css:",
        "  - css/mkdocs.css",
        "  - css/threatmodel.css",
        "extra_javascript:",
        "  - js/tm.js",
        "  - javascript/readthedocs.js",
    ]

    content = "\n".join(lines) + "\n"
    os.makedirs(outputDir, exist_ok=True)
    path = os.path.join(outputDir, filename)
    with open(path, "w") as fh:
        print(f"OUTPUT: {fh.name}")
        fh.write(content)
    return path

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
        # Proper MkDocs YAML config
        generate_mkdocs_config(tm_list, MKDocsDir, filename="mkdocs.yml")
        generateFromTMList(tm_list, outputDir, outFile="index.md", pdfArtifactLink=None)
        if pdfArtifactLink:
            # Future: unzip artifact into site
            pass
        oldwd = os.getcwd()
        os.chdir(MKDocsDir)
        if shutil.which("mkdocs"):
            os.system(f"mkdocs build --clean --config-file mkdocs.yml --site-dir={MKDocsSiteDir}")
        else:
            print("WARNING: 'mkdocs' executable not found on PATH. Skipping site build. Install mkdocs to generate the static site.")
        os.chdir(oldwd)




if __name__ == "__main__":
    main()
