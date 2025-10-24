import argparse
import os
import importlib_resources
import shutil
import yaml
import re
from os import path
from pathlib import Path
import pikepdf
import logging

logging.basicConfig(level=logging.INFO)

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
        
        new_pdf = Path(outputDir) / f"final_{outputName}.pdf"

        tmp_merged = original_pdf.with_name(f"{original_pdf.stem}.merged{original_pdf.suffix}")
        with pikepdf.open(original_pdf) as merged_pdf:
            for pdf_file in reversed(pre_pdf_files):
                with pikepdf.open(pdf_file) as pdf:
                    for page in reversed(pdf.pages):
                        merged_pdf.pages.insert(0, page)
            for pdf_file in post_pdf_files:
                with pikepdf.open(pdf_file) as pdf:
                    merged_pdf.pages.extend(pdf.pages)
            merged_pdf.save(tmp_merged)
        shutil.move(str(tmp_merged), str(new_pdf))
        logging.info(f"Final PDF with pre and post sections saved as {new_pdf}")
    else:
        print(f"No PDF files found in {assetDir0}/PDF_sections_2")

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
