import fs from 'fs';
import { exec } from 'child_process';
import { promisify } from 'util';
import ThreatModel from '../models/ThreatModel.js';
import { MarkdownRenderer } from './MarkdownRenderer.js';

const execAsync = promisify(exec);

export class PDFRenderer {
    private threatModel: ThreatModel;
    private markdownRenderer: MarkdownRenderer;

    constructor(threatModel: ThreatModel) {
        this.threatModel = threatModel;
        this.markdownRenderer = new MarkdownRenderer(threatModel);
    }

    /**
     * Renders threat model to PDF using pandoc (if available)
     * Requires pandoc to be installed: https://pandoc.org/
     */
    async renderToPDF(outputPath: string, _options?: { headerNote?: string }): Promise<void> {
        // Generate markdown
        const markdown = this.markdownRenderer.renderFullReport();
        
        // Write markdown to temp file
        const tempMdPath = outputPath.replace('.pdf', '.md');
        fs.writeFileSync(tempMdPath, markdown, 'utf8');

        try {
            // Check if pandoc is available
            await execAsync('pandoc --version');
            
            // Convert markdown to PDF using pandoc
            const pandocCommand = `pandoc "${tempMdPath}" -o "${outputPath}" --pdf-engine=xelatex -V geometry:margin=1in`;
            await execAsync(pandocCommand);
            
            console.log(`PDF generated successfully: ${outputPath}`);
        } catch (error) {
            throw new Error(
                `PDF generation failed. Make sure pandoc is installed: ${(error as Error).message}\n` +
                `Markdown file saved at: ${tempMdPath}\n` +
                `You can manually convert it to PDF using: pandoc ${tempMdPath} -o ${outputPath}`
            );
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
