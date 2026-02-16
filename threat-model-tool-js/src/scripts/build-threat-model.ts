#!/usr/bin/env node
import ThreatModel from '../models/ThreatModel.js';
import { ReportGenerator } from '../ReportGenerator.js';
import { execSync } from 'child_process';
import path from 'path';
import fs from 'fs';
import { marked } from 'marked';
import { load } from 'cheerio';

function renderMarkdownWithMdInHtml(mdSource: string): string {
    const render = (src: string): string => marked.parse(src, { gfm: true, breaks: false, async: false }) as string;

    let html = render(mdSource);

    for (let pass = 0; pass < 8; pass++) {
        const $ = load(`<root>${html}</root>`, { decodeEntities: false });
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

const args = process.argv.slice(2);
const yamlFile = args[0];
const outputDir = args[1] || './output';

if (!yamlFile) {
    console.error('Usage: build-threat-model.ts <yaml-file> [output-dir]');
    process.exit(1);
}

// Load and generate
const fullPath = path.resolve(yamlFile);
if (!fs.existsSync(fullPath)) {
    console.error(`File not found: ${fullPath}`);
    process.exit(1);
}

const tmo = new ThreatModel(fullPath);
ReportGenerator.generate(tmo, 'full', path.resolve(outputDir));

const modelId = (tmo as any)._id || (tmo as any).id;
generateHtmlFromMarkdown(path.resolve(outputDir), modelId);

// Run PlantUML via Docker
const imgDir = path.join(path.resolve(outputDir), 'img');
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

console.log('Done!');
