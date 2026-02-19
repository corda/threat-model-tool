import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { execSync } from 'child_process';
import ThreatModel from '../models/ThreatModel.js';
import { MarkdownRenderer } from './MarkdownRenderer.js';
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export class PDFRenderer {
    private threatModel: ThreatModel;
    private markdownRenderer: MarkdownRenderer;

    constructor(threatModel: ThreatModel) {
        this.threatModel = threatModel;
        this.markdownRenderer = new MarkdownRenderer(threatModel);
    }

    /**
     * Renders threat model to PDF using Puppeteer via Docker
     */
    renderToPDF(outputPath: string, options?: { headerNote?: string }): void {
        const headerNote = options?.headerNote ?? 'Private and confidential';
        const absOutputPath = path.resolve(outputPath);
        const outputDir = path.dirname(absOutputPath);
        const fileName = path.basename(absOutputPath);
        const htmlFileName = fileName.replace('.pdf', '.html');
        const absHtmlPath = path.join(outputDir, htmlFileName);

        if (!fs.existsSync(absHtmlPath)) {
            // Fallback: if HTML doesn't exist yet, we might be calling this from a context 
            // where only Markdown is expected. But the Docker approach REQUIRES HTML.
            console.warn(`HTML file not found at ${absHtmlPath}. PDF generation requires HTML when using Puppeteer.`);
            return;
        }

        const userDir = "/home/pptruser";
        
        // Find pdfScript.js. It should be in src/scripts/pdfScript.js
        const scriptSource = path.join(__dirname, '..', 'scripts', 'pdfScript.js');
        
        if (!fs.existsSync(scriptSource)) {
            throw new Error(`Puppeteer script not found at ${scriptSource}`);
        }

        // We'll copy it to a temporary location in the output directory to make mounting easier
        const tempScriptsDir = path.join(outputDir, '.scripts');
        fs.mkdirSync(tempScriptsDir, { recursive: true });
        const scriptDest = path.join(tempScriptsDir, 'pdfScript.js');
        fs.copyFileSync(scriptSource, scriptDest);

        // Pre-create the PDF file with open permissions so the Docker user (pptruser) can write to it.
        // This avoids EACCES errors when the host directory is owned by a different user than the container user.
        try {
            fs.writeFileSync(absOutputPath, '');
            fs.chmodSync(absOutputPath, 0o666);
        } catch (e) {
            console.warn(`Warning: Could not pre-create or chmod PDF file: ${e}`);
        }

        const dockerCommand = `docker run --init --platform linux/amd64 ` +
            `-v "${path.resolve(tempScriptsDir)}:${userDir}/scripts" ` +
            `-v "${path.resolve(outputDir)}:${userDir}/output" ` +
            `--rm ghcr.io/puppeteer/puppeteer:latest ` +
            `node scripts/pdfScript.js ` +
            `"file://${userDir}/output/${htmlFileName}" ` +
            `"output/${fileName}" ` +
            `"${headerNote.replace(/"/g, '\\"')}"`;

        try {
            execSync(dockerCommand, { stdio: 'inherit' });
            console.log(`PDF generated successfully: ${outputPath}`);
        } catch (error) {
            throw new Error(`Docker PDF generation failed: ${(error as Error).message}`);
        } finally {
            // Cleanup the temporary script
            try {
                fs.rmSync(tempScriptsDir, { recursive: true, force: true });
            } catch (e) {
                // Ignore cleanup errors
            }
        }
    }

    /**
     * Alternative PDF generation using markdown-pdf (Node.js library)
     * This is a fallback if pandoc is not available
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
                `Or use pandoc for PDF generation.`
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
        console.log(`To convert to PDF, run: pandoc ${outputPath} -o ${outputPath.replace('.md', '.pdf')}`);
    }
}
