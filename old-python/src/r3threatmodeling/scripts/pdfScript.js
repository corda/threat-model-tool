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
  let status = await page.goto(aurl, 
  {waitUntil: 'networkidle0'
});

  status = status.status();
  if (status != 404) {
      console.log(`HTTP response status code: ` +status );
  };


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
