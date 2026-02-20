#!/usr/bin/env node
import ThreatModel from '../models/ThreatModel.js';
import { ReportGenerator } from '../ReportGenerator.js';
import { PDFRenderer } from '../renderers/index.js';
import { execSync } from 'child_process';
import path from 'path';
import fs from 'fs';
import { marked } from 'marked';
import { load } from 'cheerio';
import { parseMultiOption } from './cli-options.js';

const DEFAULT_ASSET_FOLDER = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../assets_MD_HTML');

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

function copyDirectoryContents(sourceDir: string, destinationDir: string): void {
    if (!fs.existsSync(sourceDir) || !fs.statSync(sourceDir).isDirectory()) {
        console.warn(`Asset folder not found or not a directory, skipping: ${sourceDir}`);
        return;
    }

    fs.mkdirSync(destinationDir, { recursive: true });
    const entries = fs.readdirSync(sourceDir, { withFileTypes: true });

    for (const entry of entries) {
        const sourcePath = path.join(sourceDir, entry.name);
        const destinationPath = path.join(destinationDir, entry.name);

        if (entry.isDirectory()) {
            fs.cpSync(sourcePath, destinationPath, { recursive: true, force: true });
        } else if (entry.isFile()) {
            fs.copyFileSync(sourcePath, destinationPath);
        }
    }
}

function copyAssetFolders(assetFolders: string[], outputDir: string): void {
    for (const folder of assetFolders) {
        const resolvedFolder = path.resolve(folder);
        copyDirectoryContents(resolvedFolder, outputDir);
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
<link rel="stylesheet" href="css/threatmodel.css">
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

export interface BuildTMOptions {
    template?: string;
    visibility?: 'full' | 'public';
    mainTitle?: string;
    generatePDF?: boolean;
    headerNumbering?: boolean;
    forceToc?: boolean;
    fileName?: string;
    pdfHeaderNote?: string;
    pdfArtifactLink?: string;
    assetFolders?: string[];
    skipDiagrams?: boolean;
}

export function buildSingleTM(yamlFile: string, outputDir: string, options: BuildTMOptions = {}): void {
    const {
        template = 'full',
        visibility = 'full',
        mainTitle = '',
        generatePDF = false,
        headerNumbering = true,
        forceToc,
        fileName,
        pdfHeaderNote = 'Private and confidential',
        assetFolders = [DEFAULT_ASSET_FOLDER],
        skipDiagrams = false
    } = options;

    const fullPath = path.resolve(yamlFile);
    if (!fs.existsSync(fullPath)) {
        throw new Error(`File not found: ${fullPath}`);
    }

    const tmo = new ThreatModel(fullPath);
    (tmo as any)._visibility = visibility;

    const absOutputDir = path.resolve(outputDir);
    ReportGenerator.generate(tmo, template, absOutputDir, {
        mainTitle,
        fileName,
        // Canonical ReportGenerator switch for heading numbering.
        process_heading_numbering: headerNumbering,
        process_toc: forceToc,
        // Keep alias for backward compatibility with existing callers.
        headerNumbering,
        skipDiagrams,
    });

    copyAssetFolders(assetFolders, absOutputDir);

    const modelId = fileName || (tmo as any)._id || (tmo as any).id;
    const imgDir = path.join(absOutputDir, 'img');

    if (!skipDiagrams) {
        console.log('Generating PlantUML diagrams...');

        try {
            sanitizePumlFilesForLegacyPlantUml(imgDir);

            const pumlFiles = collectPumlFiles(imgDir);
            if (pumlFiles.length > 0) {
                const dockerRelativeQuoted = pumlFiles
                    .map(filePath => path.relative(imgDir, filePath).replace(/\\/g, '/'))
                    .map(toShellSingleQuoted)
                    .join(' ');

                const uid = typeof process.getuid === 'function' ? process.getuid() : 1000;
                const gid = typeof process.getgid === 'function' ? process.getgid() : 1000;

                console.log(`Using Docker PlantUML to render ${pumlFiles.length} diagram(s) to SVG...`);

                execSync(
                    `docker run --rm --user ${uid}:${gid} -v "${imgDir}:/data" -w /data plantuml/plantuml:sha-d2b2bcf -verbose -tsvg ${dockerRelativeQuoted}`,
                    { stdio: 'inherit' }
                );
            }
        } catch (error) {
            console.warn('PlantUML generation failed (Docker or local plantuml required)');
            if (error instanceof Error && error.message) {
                console.warn(error.message);
            }
        }
    }

    generateHtmlFromMarkdown(absOutputDir, modelId);

    // Generate PDF if requested
    if (generatePDF) {
        console.log('Generating PDF...');
        const pdfRenderer = new PDFRenderer(tmo);
        const pdfPath = path.join(absOutputDir, `${modelId}.pdf`);
        try {
            pdfRenderer.renderToPDF(pdfPath, { headerNote: pdfHeaderNote });
        } catch (err: any) {
            console.warn(`PDF generation failed: ${err.message}`);
        }
    }
}

if (import.meta.url === `file://${process.argv[1]}` || process.argv[1]?.endsWith('build-threat-model.ts') || process.argv[1]?.endsWith('threat-model-tool')) {
    // console.log('DEBUG: process.argv[1]:', process.argv[1]);
    const args = process.argv.slice(2);
    let yamlFile = '';
    let outputDir = './build';
    let mainTitle = '';
    let generatePDF = false;
    let template = 'full';
    let visibility: 'full' | 'public' = 'full';
    let headerNumbering = true;
    let skipDiagrams = false;
    let assetFolders: string[] | undefined;

    for (let i = 0; i < args.length; i++) {
        const arg = args[i];
        if (arg === '--mainTitle' && i + 1 < args.length) {
            mainTitle = args[++i];
        } else if (arg === '--generatePDF') {
            generatePDF = true;
        } else if (arg === '--skipDiagrams') {
            skipDiagrams = true;
        } else if (arg === '--no-headerNumbering') {
            headerNumbering = false;
        } else if (arg === '--headerNumbering') {
            headerNumbering = true;
        } else if (arg.startsWith('--template=') || arg === '--template') {
            template = arg.includes('=') ? arg.split('=')[1] : args[++i];
        } else if (arg.startsWith('--visibility=') || arg === '--visibility') {
            const v = arg.includes('=') ? arg.split('=')[1] : args[++i];
            visibility = v === 'public' ? 'public' : 'full';
        } else if (!yamlFile) {
            yamlFile = arg;
        } else if (outputDir === './build') {
            outputDir = arg;
        }
    }

    const parsedAssetFolders = parseMultiOption(args, 'assetFolder');
    if (parsedAssetFolders.length > 0) {
        assetFolders = parsedAssetFolders;
    }

    if (!yamlFile) {
        console.error('Usage: build-threat-model.ts <yaml-file> [output-dir (default: ./build)] [--mainTitle "Title"] [--generatePDF] [--template name] [--visibility full|public] [--no-headerNumbering] [--assetFolder <path>] [--skipDiagrams]');
        console.error('Note: defaults keep generated artifacts under ./build/* to avoid polluting source folders.');
        process.exit(1);
    }

    try {
        buildSingleTM(yamlFile, outputDir, {
            mainTitle,
            generatePDF,
            template,
            visibility,
            headerNumbering,
            assetFolders,
            skipDiagrams,
        });
        console.log('Done!');
    } catch (err: any) {
        console.error(err.message);
        process.exit(1);
    }
}
