import argparse
import os
import importlib_resources
import shutil
import yaml
import re

def generatePDF(rootTMYaml, outputDir, outputName = None):

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


    PDF_command =f"docker run -it --init -v {os.path.realpath('build/scripts')}:/home/pptruser/scripts -v \
{os.path.realpath(outputDir)}/:/home/pptruser/{outputDir} --rm ghcr.io/puppeteer/puppeteer:latest \"node scripts/pdfScript.js \
file:///home/pptruser/{outputDir}/{tmID}.html {outputDir}/{outputName}.pdf && pwd && find .\""
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


    args = CLI.parse_args()
    generatePDF(args.rootTMYaml, args.outputDir, args.outputName)



if __name__ == "__main__":
    main()
