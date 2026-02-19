const puppeteer = require('puppeteer')
const fs = require('fs');

async function printPDF(aurl, outputPath, headerNote) {
  const browser = await puppeteer.launch({
    headless: "new",
    args: [
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--allow-file-access-from-files'
    ]
  });
  const page = await browser.newPage();
  
  console.log(`Loading URL: ${aurl}`);
  let response = await page.goto(aurl, {
    waitUntil: 'networkidle0'
  });

  if (response && response.status() !== 200 && response.status() !== 0) {
    console.warn(`HTTP response status code: ${response.status()}`);
  }

  await page.pdf({
    displayHeaderFooter: true,
    footerTemplate: `
      <div style="color: lightgray; border-top: solid lightgray 0px; font-size: 10px; padding-top: 5px; text-align: center; width: 100%;">
        <span style="color: black; text-align: right;" class="pageNumber"></span>
      </div>
    `,
    headerTemplate: `
      <div style="color: lightgray; border-top: solid lightgray 0px; font-size: 10px; padding-top: 5px; text-align: center; width: 100%;">
        <span>${headerNote}</span>
      </div>
    `,
    format: 'A4',
    preferCSSPageSize: true,
    printBackground: true,
    margin: {
      top: '60px',
      bottom: '60px',
      left: '40px',
      right: '40px'
    }
  });

  // Actually we need to specify path in pdf() call or use the buffer
  const pdfBuffer = await page.pdf({
    displayHeaderFooter: true,
    footerTemplate: `
      <div style="color: lightgray; border-top: solid lightgray 0px; font-size: 10px; padding-top: 5px; text-align: center; width: 100%;">
        <span style="color: black; text-align: right;" class="pageNumber"></span>
      </div>
    `,
    headerTemplate: `
      <div style="color: lightgray; border-top: solid lightgray 0px; font-size: 10px; padding-top: 5px; text-align: center; width: 100%;">
        <span>${headerNote}</span>
      </div>
    `,
    format: 'A4',
    preferCSSPageSize: true,
    printBackground: true,
    path: outputPath,
    margin: {
        top: '60px',
        bottom: '60px',
        left: '40px',
        right: '40px'
      }
  });

  await browser.close();
  console.log(`PDF saved to: ${outputPath}`);
}

const args = process.argv.slice(2);
const aurl = args[0];
const outputPath = args[1];
const headerNote = args[2] || 'Private and confidential';

if (!aurl || !outputPath) {
  console.error("Usage: node pdfScript.js <URL> <outputPath> [headerNote]");
  process.exit(1);
}

printPDF(aurl, outputPath, headerNote).catch(err => {
  console.error(err);
  process.exit(1);
});
