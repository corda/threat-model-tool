#!/usr/bin/env node
import ThreatModel from '../models/ThreatModel.js';
import { ReportGenerator } from '../ReportGenerator.js';
import { execSync } from 'child_process';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import { marked } from 'marked';
import { load } from 'cheerio';

export interface BuildTMOptions {
    /** Report template name, default 'full' */
    template?: string;
    /** 'full' (default) or 'public' — filters out non-public content */
    visibility?: 'full' | 'public';
    /** Number headings in the output, default true */
    headerNumbering?: boolean;
    /** Override output base filename (without extension) */
    fileName?: string;
    /** Generate a PDF via Docker+Puppeteer after HTML generation */
    generatePDF?: boolean;
    /** Text shown in the PDF header on every page */
    pdfHeaderNote?: string;
    /** Reserved for future use (e.g. link to a pre-built PDF artifact) */
    pdfArtifactLink?: string;
}

function renderMarkdownWithMdInHtml(mdSource: string): string {
    const render = (src: string): string => marked.parse(src, { gfm: true, breaks: false, async: false }) as string;

    let html = render(mdSource);

    for (let pass = 0; pass < 8; pass++) {
        const $ = load(`<root>${html}</root>`);
        const nodes = $('*[markdown="1"], *[markdown="block"]');
        if (nodes.length === 0) {
            return $('root').html() || html;
        }

        nodes.each((_, element) => {
            const inner = $(element).html() || '';
            const renderedInner = render(inner).trim();
            $(element).removeAttr('markdown');
            $(element).html(renderedInner);
        });

        const next = $('root').html() || html;
        if (next === html) {
            break;
        }
        html = next;
    }

    return html;
}

function stripMarkdownAttributes(html: string): string {
    return html.replace(/\s+markdown=("|')(?:1|block)\1/g, '');
}

function collectPumlFiles(dir: string): string[] {
    if (!fs.existsSync(dir)) {
        return [];
    }
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    const files: string[] = [];
    for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);
        if (entry.isDirectory()) {
            files.push(...collectPumlFiles(fullPath));
        } else if (entry.isFile() && entry.name.endsWith('.puml')) {
            files.push(fullPath);
        }
    }
    return files;
}

function sanitizePumlForLegacyPlantUml(content: string): string {
    let output = content;

    output = output.replace(/^\s*!theme\s+.*$/gim, '');

    output = output.replace(
        /\n?skinparam\s+note\s*\{[\s\S]*?condition\s+note_Threat[\s\S]*?\}\n?/gi,
        '\n'
    );

    output = output.replace(
        /^\s*note\s+over\s+([^\n<]+)\s*<<\s*note_Threat\s*>>\s*$/gim,
        'note over $1 #FFE0E0'
    );

    return output;
}

function sanitizePumlFilesForLegacyPlantUml(imgDir: string): void {
    const pumlFiles = collectPumlFiles(imgDir);
    for (const filePath of pumlFiles) {
        const original = fs.readFileSync(filePath, 'utf-8');
        const sanitized = sanitizePumlForLegacyPlantUml(original);
        if (sanitized !== original) {
            fs.writeFileSync(filePath, sanitized, 'utf-8');
        }
    }
}

function toShellSingleQuoted(value: string): string {
    return `'${value.replace(/'/g, `'"'"'`)}'`;
}

function generatePDFFromHtml(outputDir: string, modelId: string, options: BuildTMOptions): void {
    const htmlPath = path.join(outputDir, `${modelId}.html`);
    if (!fs.existsSync(htmlPath)) {
        console.warn(`HTML file missing, PDF not generated: ${htmlPath}`);
        return;
    }

    // Locate pdfScript.js next to this script file
    const scriptDir = path.dirname(fileURLToPath(import.meta.url));
    const pdfScriptSrc = path.join(scriptDir, 'pdfScript.js');
    if (!fs.existsSync(pdfScriptSrc)) {
        console.warn(`pdfScript.js not found at ${pdfScriptSrc}, skipping PDF generation`);
        return;
    }

    // Write pdfScript.js into a scripts/ subdirectory of outputDir so Docker can mount it
    const scriptsDir = path.join(outputDir, 'scripts');
    fs.mkdirSync(scriptsDir, { recursive: true });
    fs.copyFileSync(pdfScriptSrc, path.join(scriptsDir, 'pdfScript.js'));

    const pdfName = `${modelId}.pdf`;
    const pdfOutPath = path.join(outputDir, pdfName);
    const headerNote = options.pdfHeaderNote ?? 'Private and confidential';

    // Inside the container, outputDir is mounted at /home/pptruser/out
    const containerHtmlUrl = `file:///home/pptruser/out/${modelId}.html`;
    const containerPdfPath = `out/${pdfName}`;
    const containerScriptsPath = `/home/pptruser/scripts`;

    try {
        // The puppeteer container runs as pptruser (uid 10042).  Make the
        // output directory world-writable so it can create the PDF file,
        // then restore the original permissions afterwards.
        const origMode = fs.statSync(outputDir).mode;
        fs.chmodSync(outputDir, 0o777);

        try {
            execSync(
                `docker run --init --rm ` +
                `-v ${toShellSingleQuoted(outputDir)}:/home/pptruser/out ` +
                `-v ${toShellSingleQuoted(scriptsDir)}:${containerScriptsPath} ` +
                `ghcr.io/puppeteer/puppeteer:latest ` +
                `node scripts/pdfScript.js ` +
                `${toShellSingleQuoted(containerHtmlUrl)} ` +
                `${toShellSingleQuoted(containerPdfPath)} ` +
                `${toShellSingleQuoted(headerNote)}`,
                { stdio: 'inherit' }
            );
            console.log(`Generated PDF: ${pdfOutPath}`);
        } finally {
            fs.chmodSync(outputDir, origMode);
        }
    } catch (error) {
        console.warn(`PDF generation failed (Docker + ghcr.io/puppeteer/puppeteer:latest required): ${error}`);
    }
}

function generateHtmlFromMarkdown(outputDir: string, modelId: string): void {
    const mdPath = path.join(outputDir, `${modelId}.md`);
    const htmlPath = path.join(outputDir, `${modelId}.html`);

    if (!fs.existsSync(mdPath)) {
        console.warn(`Markdown file missing, HTML not generated: ${mdPath}`);
        return;
    }

    const mdReport = fs.readFileSync(mdPath, 'utf-8');
    const htmlBody = stripMarkdownAttributes(renderMarkdownWithMdInHtml(mdReport));
    const baseHtml = `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8" />
<link rel="stylesheet" href="css/tm.css">
<link rel="stylesheet" href="css/github.min.css">
<script src="js/highlight.min.js"></script>
<script>hljs.highlightAll();</script>
</head>
<body>%BODY%</body>
</html>
`;

    fs.writeFileSync(htmlPath, baseHtml.replace('%BODY%', htmlBody), 'utf8');
    console.log(`Generated: ${htmlPath}`);
}

function buildSingleTM(yamlFile: string, outputDir: string = './output', options: BuildTMOptions = {}): void {
    const {
        template = 'full',
        visibility = 'full',
        headerNumbering = true,
        fileName,
        generatePDF = false,
        pdfHeaderNote,
        pdfArtifactLink,
    } = options;

    const fullPath = path.resolve(yamlFile);
    if (!fs.existsSync(fullPath)) {
        console.error(`File not found: ${fullPath}`);
        process.exit(1);
    }

    const isPublic = visibility === 'public';
    const tmo = new ThreatModel(fullPath, null, isPublic);
    ReportGenerator.generate(tmo, template, path.resolve(outputDir), { process_heading_numbering: headerNumbering });

    const modelId: string = fileName ?? ((tmo as any)._id || (tmo as any).id);
    const absOutputDir = path.resolve(outputDir);

    // Run PlantUML first so SVGs exist before HTML/PDF generation
    const imgDir = path.join(absOutputDir, 'img');
    console.log('Generating PlantUML diagrams...');

    try {
        sanitizePumlFilesForLegacyPlantUml(imgDir);

        const pumlFiles = collectPumlFiles(imgDir);
        if (pumlFiles.length > 0) {
            const quoted = pumlFiles.map(toShellSingleQuoted).join(' ');
            try {
                execSync(`plantuml -tsvg ${quoted}`, { stdio: 'inherit' });
            } catch (e) {
                console.log('Local plantuml failed, trying docker...');
                execSync(`docker run --rm -v "${imgDir}:/data" plantuml/plantuml:sha-d2b2bcf *.puml -tsvg`, {
                    stdio: 'inherit'
                });
            }
        }
    } catch (error) {
        console.warn('PlantUML generation failed (Docker or local plantuml required)');
    }

    generateHtmlFromMarkdown(absOutputDir, modelId);

    if (generatePDF) {
        generatePDFFromHtml(absOutputDir, modelId, { pdfHeaderNote, pdfArtifactLink });
    }

    console.log('Done!');
}

export { buildSingleTM };

// Only run CLI when this file is the entry point
const isMain = process.argv[1] && (
    process.argv[1].endsWith('build-threat-model.ts') ||
    process.argv[1].endsWith('build-threat-model.js')
);
if (isMain) {
    const args = process.argv.slice(2);
    let yamlFile = '';
    let outputDir = './output';
    const options: BuildTMOptions = {};

    for (let i = 0; i < args.length; i++) {
        const arg = args[i];
        if (arg.startsWith('--template=')) {
            options.template = arg.split('=')[1];
        } else if (arg.startsWith('--visibility=')) {
            options.visibility = arg.split('=')[1] as 'full' | 'public';
        } else if (arg.startsWith('--fileName=')) {
            options.fileName = arg.split('=')[1];
        } else if (arg === '--generatePDF') {
            options.generatePDF = true;
        } else if (arg.startsWith('--pdfHeaderNote=')) {
            options.pdfHeaderNote = arg.split('=')[1];
        } else if (!yamlFile) {
            yamlFile = arg;
        } else if (outputDir === './output') {
            outputDir = arg;
        }
    }

    if (!yamlFile) {
        console.error('Usage: build-threat-model.ts <yaml-file> [output-dir] [--template=...] [--visibility=...]');
        process.exit(1);
    }

    buildSingleTM(yamlFile, outputDir, options);
}
