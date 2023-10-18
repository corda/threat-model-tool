import argparse
import os
import importlib_resources
import shutil
import yaml
import re

def generatePDF(rootTMYaml, outputDir, outputName = None, headerNote=""):

    print("Generating PDF from html version")
    rootTMYaml.seek(0)
    tm = yaml.safe_load(rootTMYaml)
    tmID = tm['ID']

    if not outputName:
      title = tm['title']
      version = tm['version']
      outputName = f'{title} Threat Model-{version}'
      outputName = re.sub('[^\w_.)(_-]', '_', outputName)   # replace invalid chars with underscore
      
    os.makedirs(  "build/scripts", exist_ok=True)
    PDFscript = importlib_resources.files('r3threatmodeling').joinpath('scripts/pdfScript.js')
    shutil.copy(PDFscript, 'build/scripts/pdfScript.js')

    os.system(f"touch {outputDir}/{outputName}.pdf")
    os.system(f"chmod 666 {outputDir}/{outputName}.pdf")

    userDir ="/home/pptruser"

    PDF_command =f"docker run --init -v {os.path.realpath('build/scripts')}:{userDir}/scripts -v \
{os.path.realpath(outputDir)}/:{userDir}/{outputDir} --rm ghcr.io/puppeteer/puppeteer:latest node scripts/pdfScript.js \
file://{userDir}/{outputDir}/{tmID}.html {outputDir}/{outputName}.pdf '{headerNote}'"
    print(f"Executing command: {PDF_command}")
    os.system(PDF_command)

def main():
    CLI=argparse.ArgumentParser()

    CLI.add_argument(
    "--rootTMYaml",
    default = None,
    required=True,
    type=open
    )

    CLI.add_argument(
    "--outputDir", 
    default = "build",
    required=False
    )

    CLI.add_argument(
    "--outputName", 
    default = None,
    required=False
    )

    CLI.add_argument(
    "--headerNote", 
    default = "Private and confidential",
    required=False
    )

    args = CLI.parse_args()
    generatePDF(args.rootTMYaml, args.outputDir, args.outputName, args.headerNote)



if __name__ == "__main__":
    main()
