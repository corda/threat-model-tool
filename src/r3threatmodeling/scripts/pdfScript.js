const puppeteer = require('puppeteer')
const fs = require('fs');
const { url } = require('inspector');

async function printPDF(aurl, headerNote) {
  const browser = await puppeteer.launch({
    headless: "new", args: [
      '--no-sandbox',
      '--disable-setuid-sandbox'
    ]
  });
  const page = await browser.newPage();
  await page.goto(aurl, 
  {waitUntil: 'networkidle0'});
  const pdf = await page.pdf(
    
    // {
    //  format: 'A4',
    //  preferCSSPageSize: true
    // }

    {
      displayHeaderFooter: true,
      footerTemplate: `
        <div style="color: lightgray; border-top: solid lightgray 0px; font-size: 10px; padding-top: 5px; text-align: center; width: 100%;">
          <span style="color: black; text-align: right;" class="pageNumber"></span>
        </div>
      `,
      headerTemplate: `
      <div style="color: lightgray; border-top: solid lightgray 0px; font-size: 10px; padding-top: 5px; text-align: center; width: 100%;">
      <span> ` + headerNote +`</span>
      </div>
    `,
      format: 'A4',
      preferCSSPageSize: true,
      // margin: {
      //   bottom: 70, // minimum required for footer msg to display
      //   left: 25,
      //   right: 35,
      //   top: 30,
      // },
      printBackground: true,
    }
    
    
    
    
    );
 
  await browser.close();
  return pdf;
}

async function main(argv){
  aurl = argv[2]
  fileName = argv[3]
  // timeGen = argv[4]
  headerNote = argv[4]
  console.log("URL: " + aurl)
  console.log("fileName: " + fileName)
  console.log("headerNote: " + headerNote)
  data = await printPDF(aurl, headerNote);

  fs.writeFileSync(fileName, data);
}

main(process.argv)
