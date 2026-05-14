import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { execFileSync } from 'child_process';
import ThreatModel from '../models/ThreatModel.js';
import { MarkdownRenderer } from './MarkdownRenderer.js';
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/**
 * Build the argv list for the puppeteer-in-docker call used by
 * `PDFRenderer.renderToPDF`. Exported separately so the argv composition can
 * be unit-tested without spawning docker: each substituted value (mount path,
 * output paths, header note) is passed as a discrete argv entry to
 * `execFileSync`, so shell metacharacters cannot escape the call.
 */
export function buildPuppeteerDockerArgs(params: {
    tempScriptsDir: string;
    outputDir: string;
    containerUser: string;
    image: string;
    htmlFileName: string;
    fileName: string;
    headerNote: string;
}): string[] {
    const { tempScriptsDir, outputDir, containerUser, image, htmlFileName, fileName, headerNote } = params;
    return [
        'run', '--init', '--cap-add=SYS_ADMIN',
        '-v', `${path.resolve(tempScriptsDir)}:${containerUser}/scripts`,
        '-v', `${path.resolve(outputDir)}:${containerUser}/output`,
        '-w', containerUser,
        '--rm', image,
        'node', 'scripts/pdfScript.mjs',
        `file://${containerUser}/output/${htmlFileName}`,
        `${containerUser}/output/${fileName}`,
        headerNote,
    ];
}

export class PDFRenderer {
    private threatModel: ThreatModel;
    private markdownRenderer: MarkdownRenderer;

    constructor(threatModel: ThreatModel) {
        this.threatModel = threatModel;
        this.markdownRenderer = new MarkdownRenderer(threatModel);
    }

    /**
     * Renders threat model to PDF using Puppeteer via Docker (with local fallback)
     */
    renderToPDF(outputPath: string, options?: { headerNote?: string }): void {
        const headerNote = options?.headerNote ?? 'Private and confidential';
        const absOutputPath = path.resolve(outputPath);
        const outputDir = path.dirname(absOutputPath);
        const fileName = path.basename(absOutputPath);
        const htmlFileName = fileName.replace('.pdf', '.html');
        const absHtmlPath = path.join(outputDir, htmlFileName);

        if (!fs.existsSync(absHtmlPath)) {
            console.warn(`HTML file not found at ${absHtmlPath}. PDF generation requires HTML when using Puppeteer.`);
            return;
        }

        // Find pdfScript.mjs (ESM module). It should be in dist/scripts/pdfScript.mjs
        const scriptSource = path.join(__dirname, '..', 'scripts', 'pdfScript.mjs');
        
        if (!fs.existsSync(scriptSource)) {
            throw new Error(`Puppeteer script not found at ${scriptSource}`);
        }

        // Copy script to temp directory for Docker mounting
        const tempScriptsDir = path.join(outputDir, '.scripts');
        fs.mkdirSync(tempScriptsDir, { recursive: true });
        const scriptDest = path.join(tempScriptsDir, 'pdfScript.mjs');
        fs.copyFileSync(scriptSource, scriptDest);

        // Pre-create PDF file with open permissions for Docker user
        try {
            fs.writeFileSync(absOutputPath, '');
            fs.chmodSync(absOutputPath, 0o666);
        } catch (e) {
            console.warn(`Warning: Could not pre-create PDF file: ${e}`);
        }

        // Select Docker image based on host architecture.
        // ghcr.io/puppeteer/puppeteer is amd64-only; zenika/alpine-chrome is multi-arch.
        const isArm64 = process.arch === 'arm64';
        const image = isArm64
            ? 'zenika/alpine-chrome:with-puppeteer'
            : 'ghcr.io/puppeteer/puppeteer:latest';
        const containerUser = isArm64 ? '/usr/src/app' : '/home/pptruser';

        // Build the docker invocation as an explicit argv list and run it
        // without a shell. Previously this was a single command string passed
        // to execSync, with only `"` escaped on headerNote — `$(...)`,
        // backticks, `;`, and `&&` in any of the substituted values would
        // still execute against the host shell. Using execFileSync with a
        // string array bypasses the shell entirely and removes the injection
        // surface for callers that route untrusted strings through
        // `options.headerNote` or the resolved paths.
        const dockerArgs = buildPuppeteerDockerArgs({
            tempScriptsDir,
            outputDir,
            containerUser,
            image,
            htmlFileName,
            fileName,
            headerNote,
        });

        try {
            execFileSync('docker', dockerArgs, { stdio: 'inherit', timeout: 300000 });
            console.log(`PDF generated successfully: ${outputPath}`);
        } catch (error) {
            throw new Error(`Docker PDF generation failed: ${(error as Error).message}`);
        } finally {
            // Cleanup temporary script
            try {
                fs.rmSync(tempScriptsDir, { recursive: true, force: true });
            } catch (e) {
                // Ignore cleanup errors
            }
        }
    }

    /**
     * Alternative PDF generation using markdown-pdf (Node.js library)
        * This is an optional alternative to the Docker Puppeteer flow
     */
    async renderToPDFWithNodeLibrary(outputPath: string): Promise<void> {
        const markdown = this.markdownRenderer.renderFullReport();
        
        // Note: This requires markdown-pdf package
        // npm install markdown-pdf
        
        try {
            // Dynamic import to avoid hard dependency (using string to bypass TypeScript check)
            const importPath = 'markdown-pdf';
            const markdownpdf: any = await import(importPath);
            
            return new Promise((resolve, reject) => {
                markdownpdf.default()
                    .from.string(markdown)
                    .to(outputPath, (err: Error) => {
                        if (err) {
                            reject(new Error(`PDF generation failed: ${err.message}`));
                        } else {
                            console.log(`PDF generated successfully: ${outputPath}`);
                            resolve();
                        }
                    });
            });
        } catch (error) {
            throw new Error(
                `markdown-pdf library not found. Install it with: npm install markdown-pdf\n` +
                `Or use the default Docker Puppeteer PDF generation path.`
            );
        }
    }

    /**
     * Saves markdown content for manual PDF conversion
     */
    saveMarkdownForPDFConversion(outputPath: string): void {
        const markdown = this.markdownRenderer.renderFullReport();
        fs.writeFileSync(outputPath, markdown, 'utf8');
        console.log(`Markdown saved to: ${outputPath}`);
        console.log('Convert this Markdown using your preferred toolchain if you need a manual PDF workflow.');
    }
}
