import puppeteer from 'puppeteer';

const TIMEOUT_MS = 180000;

async function launchBrowser() {
  const baseArgs = ['--allow-file-access-from-files'];
  const linuxOnlyArgs = ['--no-sandbox', '--disable-setuid-sandbox'];
  const args = process.platform === 'linux' ? [...baseArgs, ...linuxOnlyArgs] : baseArgs;

  try {
    return await puppeteer.launch({
      headless: true,
      protocolTimeout: TIMEOUT_MS,
      args
    });
  } catch (err) {
    if (process.platform === 'darwin') {
      console.warn('Default browser launch failed. Retrying with system Chrome channel...');
      return puppeteer.launch({
        headless: true,
        protocolTimeout: TIMEOUT_MS,
        channel: 'chrome',
        args
      });
    }
    throw err;
  }
}

async function printPDF(aurl, outputPath, headerNote) {
  const browser = await launchBrowser();
  const page = await browser.newPage();

  page.setDefaultTimeout(TIMEOUT_MS);
  page.setDefaultNavigationTimeout(TIMEOUT_MS);

  await page.setRequestInterception(true);
  page.on('request', (req) => {
    const url = req.url();
    if (url.startsWith('http://') || url.startsWith('https://')) {
      req.abort();
      return;
    }
    req.continue();
  });

  console.log(`Loading URL: ${aurl}`);
  const response = await page.goto(aurl, {
    waitUntil: 'domcontentloaded',
    timeout: TIMEOUT_MS
  });

  await new Promise((resolve) => setTimeout(resolve, 3000));

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
    path: outputPath,
    timeout: TIMEOUT_MS,
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
  console.error('Usage: node pdfScript.js <URL> <outputPath> [headerNote]');
  process.exit(1);
}

printPDF(aurl, outputPath, headerNote).catch((err) => {
  console.error(err);
  process.exit(1);
});
