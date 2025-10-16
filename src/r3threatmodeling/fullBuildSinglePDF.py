import argparse
import os
import importlib_resources
import shutil
import yaml
import re
from os import path
from pathlib import Path
from PyPDF2 import PdfMerger

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

    # Post-process the generated PDF report
    # Include md from <main folder>/assets/markdown_sections_1/pre_NN_*.md on top of the document
    # Include md from <main folder>/assets/markdown_sections_1/post_NN_*.md at the end of the document

    assetDir0 = os.path.dirname(rootTMYaml.name) + "/assets"
    if Path(f"{assetDir0}/PDF_sections_2").exists():

        pre_pdf_files = sorted(Path(f"{assetDir0}/PDF_sections_2").glob("pre_??_*.pdf"))
        post_pdf_files = sorted(Path(f"{assetDir0}/PDF_sections_2").glob("post_??_*.pdf"))

        original_pdf = Path(outputDir) / f"{outputName}.pdf"

        merger = PdfMerger()

        try:
            # Append pre PDF files
            for pdf_file in pre_pdf_files:
                merger.append(str(pdf_file))

            # Append the original PDF
            merger.append(str(original_pdf))

            # Append post PDF files
            for pdf_file in post_pdf_files:
                merger.append(str(pdf_file))

            # Write merged PDF to a temporary file and atomically replace original
            tmp_merged = original_pdf.with_name(f"{original_pdf.stem}.merged{original_pdf.suffix}")
            with open(tmp_merged, "wb") as fout:
                merger.write(fout)

            shutil.move(str(tmp_merged), str(original_pdf))
        finally:
            merger.close()

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
