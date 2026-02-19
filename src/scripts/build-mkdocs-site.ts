#!/usr/bin/env node
/**
 * build-mkdocs-site.ts
 *
 * Discovers threat models in a directory, builds each one, then generates
 * a MkDocs static site using the same legacy ReadTheDocs theme/CSS/JS
 * setup as the Python implementation.
 *
 * CLI usage:
 *   tsx src/scripts/build-mkdocs-site.ts \
 *     --TMDirectory ./threatModels \
 *     --MKDocsDir   ./build/mkdocs \
 *     --MKDocsSiteDir ./build/site-mkdocs \
 *     [--template MKdocs] \
 *     [--visibility full|public] \
 *     [--templateSiteFolderSRC ../tests/siteTemplate/mkdocs] \
 *     [--templateSiteFolderDST ./build/mkdocs] \
 *     [--headerNumbering] \
 *     [--generatePDF]
 *
 * Note: default outputs are under ./build/* to avoid polluting source folders.
 */

import path from 'path';
import fs from 'fs';
import { execSync } from 'child_process';
import { fileURLToPath } from 'url';
import yaml from 'js-yaml';
import { buildSingleTM, type BuildTMOptions } from './build-threat-model.js';
import { parseFlag, parseOption } from './cli-options.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

interface TMEntry {
    name: string;
    yamlPath: string;
    id: string;
    title: string;
}

interface StagedTMEntry extends TMEntry {
    hasPdf: boolean;
}

function getParentMkdocsInitDir(): string {
    // Assets are located in src/assets_MKDOCS_init
    return path.resolve(__dirname, '..', 'assets_MKDOCS_init');
}

function copyDirRecursive(src: string, dest: string): void {
    fs.mkdirSync(dest, { recursive: true });
    for (const entry of fs.readdirSync(src, { withFileTypes: true })) {
        const srcPath = path.join(src, entry.name);
        const destPath = path.join(dest, entry.name);
        if (entry.isDirectory()) {
            copyDirRecursive(srcPath, destPath);
        } else {
            fs.copyFileSync(srcPath, destPath);
        }
    }
}

function extractTMMetadata(yamlPath: string): { id: string; title: string } {
    const content = fs.readFileSync(yamlPath, 'utf-8');
    const doc = yaml.load(content) as Record<string, unknown>;
    const fileStem = path.basename(yamlPath, path.extname(yamlPath));

    const idValue = typeof doc?.ID === 'string' ? doc.ID : fileStem;
    const titleValue = typeof doc?.title === 'string' ? doc.title : idValue;

    return { id: idValue, title: titleValue };
}

function discoverTMs(tmDirectory: string): TMEntry[] {
    const absDir = path.resolve(tmDirectory);
    if (!fs.existsSync(absDir)) {
        console.error(`TMDirectory not found: ${absDir}`);
        process.exit(1);
    }

    const tmList: TMEntry[] = [];
    for (const entry of fs.readdirSync(absDir, { withFileTypes: true })) {
        if (!entry.isDirectory()) continue;

        const yamlPath = path.join(absDir, entry.name, `${entry.name}.yaml`);
        if (!fs.existsSync(yamlPath)) continue;

        const meta = extractTMMetadata(yamlPath);
        tmList.push({
            name: entry.name,
            yamlPath,
            id: meta.id,
            title: meta.title,
        });
    }

    tmList.sort((a, b) => a.name.localeCompare(b.name));
    return tmList;
}

function yamlQuote(value: string): string {
    if (value.length === 0) return '""';
    if (/[:{}\[\],&*#!|>'"%@`]/.test(value)) {
        return `"${value.replace(/"/g, '\\"')}"`;
    }
    return value;
}

function writeMkdocsConfig(
    tmList: TMEntry[],
    mkdocsDir: string,
    siteName: string,
    docsDirSetting: string
): void {
    const lines: string[] = [
        `site_name: ${yamlQuote(siteName)}`,
        `docs_dir: ${docsDirSetting}`,
        'use_directory_urls: false',
        'nav:',
        '  - Home: index.md',
    ];

    const sorted = [...tmList].sort((a, b) => (a.title || a.id).localeCompare(b.title || b.id));
    for (const tm of sorted) {
        lines.push(`  - ${yamlQuote(tm.title)}: ${tm.id}/index.md`);
    }

    lines.push(
        '',
        'theme:',
        '  name: readthedocs',
        'markdown_extensions:',
        '  - attr_list',
        '  - toc:',
        '      baselevel: 1',
        '      toc_depth: 5',
        '  - md_in_html',
        'plugins:',
        '  - search',
        'extra_css:',
        '  - css/mkdocs.css',
        '  - css/threatmodel.css',
        'extra_javascript:',
        '  - js/tm.js',
        '  - javascript/readthedocs.js',
        ''
    );

    fs.writeFileSync(path.join(mkdocsDir, 'mkdocs.yml'), lines.join('\n'), 'utf-8');
}

function writeIndexMarkdown(tmList: StagedTMEntry[], docsDir: string, pdfArtifactLink?: string): void {
    const lines: string[] = ['# Threat Models Index', ''];
    if (pdfArtifactLink) {
        lines.push(`PDF Artifact: ${pdfArtifactLink}`, '');
    }

    const sorted = [...tmList].sort((a, b) => (a.title || a.id).localeCompare(b.title || b.id));
    for (const tm of sorted) {
        const links: string[] = [];
        links.push(`[HTML](${tm.id}/${tm.id}.html)`);
        if (tm.hasPdf) {
            links.push(`[PDF](${tm.id}/${tm.id}.pdf)`);
        }
        lines.push(`* **${tm.title}** — ${links.join(' | ')}`);
    }
    lines.push('');

    fs.writeFileSync(path.join(docsDir, 'index.md'), lines.join('\n'), 'utf-8');
}

function resolveBuiltMarkdown(tmStagingDir: string, tm: TMEntry): string | null {
    const candidates = [
        path.join(tmStagingDir, `${tm.id}.md`),
        path.join(tmStagingDir, `${tm.name}.md`),
    ];

    for (const candidate of candidates) {
        if (fs.existsSync(candidate)) return candidate;
    }

    const firstMd = fs.readdirSync(tmStagingDir).find(name => name.toLowerCase().endsWith('.md'));
    return firstMd ? path.join(tmStagingDir, firstMd) : null;
}

function rewriteTmLocalAssetRefs(content: string, tmId: string): string {
    const tmAssetPrefix = `/${tmId}/`;

    return content
        .replace(/\b(src|data)\s*=\s*"(?:\.\/)?img\//g, `$1="${tmAssetPrefix}img/`)
        .replace(/\b(src|data)\s*=\s*'(?:\.\/)?img\//g, `$1='${tmAssetPrefix}img/`)
        .replace(/\((?:\.\/)?img\//g, `(${tmAssetPrefix}img/`)
        .replace(/\b(src|data)\s*=\s*"(?:\.\/)?assets\//g, `$1="${tmAssetPrefix}assets/`)
        .replace(/\b(src|data)\s*=\s*'(?:\.\/)?assets\//g, `$1='${tmAssetPrefix}assets/`)
        .replace(/\((?:\.\/)?assets\//g, `(${tmAssetPrefix}assets/`);
}

function stageTM(
    tmStagingDir: string,
    tm: TMEntry,
    docsDir: string,
    options: { expectPdf?: boolean } = {}
): StagedTMEntry | null {
    const mdSource = resolveBuiltMarkdown(tmStagingDir, tm);
    if (!mdSource) {
        console.warn(`No markdown output found for ${tm.name}; skipping`);
        return null;
    }

    const tmDocsDir = path.join(docsDir, tm.id);
    fs.mkdirSync(tmDocsDir, { recursive: true });

    const mdContent = fs.readFileSync(mdSource, 'utf-8');
    const rewrittenMdContent = rewriteTmLocalAssetRefs(mdContent, tm.id);
    fs.writeFileSync(path.join(tmDocsDir, 'index.md'), rewrittenMdContent, 'utf-8');

    const htmlSource = path.join(tmStagingDir, `${tm.id}.html`);
    if (fs.existsSync(htmlSource)) {
        const htmlContent = fs.readFileSync(htmlSource, 'utf-8');
        const rewrittenHtmlContent = rewriteTmLocalAssetRefs(htmlContent, tm.id);
        fs.writeFileSync(path.join(tmDocsDir, `${tm.id}.html`), rewrittenHtmlContent, 'utf-8');
    }

    let hasPdf = false;
    const pdfSourceCandidates = [
        path.join(tmStagingDir, `${tm.id}.pdf`),
        path.join(tmStagingDir, `${tm.name}.pdf`),
    ];
    const pdfSource = pdfSourceCandidates.find(candidate => fs.existsSync(candidate));
    if (pdfSource) {
        fs.copyFileSync(pdfSource, path.join(tmDocsDir, `${tm.id}.pdf`));
        hasPdf = true;
    } else if (options.expectPdf) {
        console.warn(`PDF not found for ${tm.name}; index will include HTML only.`);
    }

    for (const folder of ['img', 'css', 'js', 'assets']) {
        const src = path.join(tmStagingDir, folder);
        if (fs.existsSync(src)) {
            copyDirRecursive(src, path.join(tmDocsDir, folder));
        }
    }

    return { ...tm, hasPdf };
}

function hasMkdocsOnPath(): boolean {
    try {
        execSync('mkdocs --version', { stdio: 'ignore' });
        return true;
    } catch {
        return false;
    }
}

export interface MkdocsSiteOptions extends BuildTMOptions {
    siteName?: string;
    MKDocsDir?: string;
    MKDocsSiteDir?: string;
    templateSiteFolderSRC?: string;
    templateSiteFolderDST?: string;
}

export function buildMkdocsSite(
    tmDirectory: string,
    outputDir?: string,
    options: MkdocsSiteOptions = {}
): void {
    const {
        siteName = 'Threat Models',
        MKDocsDir = './build/mkdocs',
        MKDocsSiteDir = './build/site-mkdocs',
        templateSiteFolderSRC,
        templateSiteFolderDST,
        template = 'MKdocs',
        pdfArtifactLink,
        headerNumbering = false,
        ...tmOptions
    } = options;

    const absMkdocsDir = path.resolve(MKDocsDir);
    const absMkdocsSiteDir = path.resolve(MKDocsSiteDir);
    const absDocsDir = path.resolve(outputDir ?? path.join(absMkdocsDir, 'docs'));
    const absTemplateDst = path.resolve(templateSiteFolderDST ?? absMkdocsDir);

    console.log(`\n${'='.repeat(60)}`);
    console.log('Building MkDocs documentation site');
    console.log(`TM Directory       : ${path.resolve(tmDirectory)}`);
    console.log(`MkDocs config dir  : ${absMkdocsDir}`);
    console.log(`MkDocs docs dir    : ${absDocsDir}`);
    console.log(`MkDocs site output : ${absMkdocsSiteDir}`);
    console.log('='.repeat(60));

    const tmList = discoverTMs(tmDirectory);
    if (tmList.length === 0) {
        console.warn('No threat models found. Aborting.');
        return;
    }

    fs.mkdirSync(absMkdocsDir, { recursive: true });
    fs.mkdirSync(absDocsDir, { recursive: true });

    const mkdocsInit = getParentMkdocsInitDir();
    if (!fs.existsSync(mkdocsInit)) {
        console.error(`Legacy MkDocs init assets not found: ${mkdocsInit}`);
        process.exit(1);
    }

    copyDirRecursive(mkdocsInit, absTemplateDst);
    if (templateSiteFolderSRC) {
        const absTemplateSrc = path.resolve(templateSiteFolderSRC);
        if (!fs.existsSync(absTemplateSrc)) {
            console.warn(`Template site folder not found: ${absTemplateSrc}`);
        } else {
            copyDirRecursive(absTemplateSrc, absTemplateDst);
        }
    }

    if (fs.existsSync(absDocsDir)) {
        for (const name of fs.readdirSync(absDocsDir)) {
            if (name === 'css' || name === 'js' || name === 'img') continue;
            fs.rmSync(path.join(absDocsDir, name), { recursive: true, force: true });
        }
    }

    const stagingDir = path.join(absMkdocsDir, '.staging');
    fs.mkdirSync(stagingDir, { recursive: true });

    const staged: StagedTMEntry[] = [];
    const built: Array<{ tm: TMEntry; tmStagingDir: string }> = [];
    for (const tm of tmList) {
        console.log(`\n--- Building ${tm.name} ---`);
        const tmStagingDir = path.join(stagingDir, tm.name);
        fs.mkdirSync(tmStagingDir, { recursive: true });

        try {
            buildSingleTM(tm.yamlPath, tmStagingDir, { ...tmOptions, template, headerNumbering });
            built.push({ tm, tmStagingDir });
        } catch (err) {
            console.error(`ERROR building ${tm.name}: ${err}`);
        }
    }

    for (const entry of built) {
        const stagedTm = stageTM(entry.tmStagingDir, entry.tm, absDocsDir, {
            expectPdf: Boolean(tmOptions.generatePDF),
        });
        if (stagedTm) {
            staged.push(stagedTm);
        }
    }

    fs.rmSync(stagingDir, { recursive: true, force: true });

    if (staged.length === 0) {
        console.error('No threat models were staged; aborting MkDocs generation.');
        process.exit(1);
    }

    const docsDirSetting = path.relative(absMkdocsDir, absDocsDir).replace(/\\/g, '/');
    writeMkdocsConfig(staged, absMkdocsDir, siteName, docsDirSetting || 'docs');
    writeIndexMarkdown(staged, absDocsDir, pdfArtifactLink);

    if (!hasMkdocsOnPath()) {
        console.warn("WARNING: 'mkdocs' executable not found on PATH. Skipping site build.");
        console.warn(`MkDocs workspace prepared in: ${absMkdocsDir}`);
        return;
    }

    fs.mkdirSync(absMkdocsSiteDir, { recursive: true });
    execSync(`mkdocs build --clean --config-file mkdocs.yml --site-dir=${JSON.stringify(absMkdocsSiteDir)}`, {
        cwd: absMkdocsDir,
        stdio: 'inherit',
    });

    console.log(`\nSite built successfully → ${absMkdocsSiteDir}`);
    console.log(`\n${'='.repeat(60)}`);
    console.log('MkDocs site generation complete!');
    console.log(`Open ${absMkdocsSiteDir}/index.html to view the site.`);
    console.log('='.repeat(60));
}

const cliArgs = process.argv.slice(2);

if (parseFlag(cliArgs, 'help') || parseFlag(cliArgs, 'h')) {
    console.log(`
Usage: build-mkdocs-site.ts [options]

Defaults: generated outputs are written under ./build/* unless overridden.

Options:
  --TMDirectory <path>              Directory containing TM sub-folders (default: .)
  --outputDir <path>                MkDocs docs source directory (default: <MKDocsDir>/docs)
    --MKDocsDir <path>                MkDocs working dir containing mkdocs.yml (default: ./build/mkdocs)
    --MKDocsSiteDir <path>            Final generated static site output (default: ./build/site-mkdocs)
  --template <name>                 Report template (default: MKdocs)
  --visibility full|public          Content visibility (default: full)
  --siteName <text>                 Site title in mkdocs.yml (default: Threat Models)
  --templateSiteFolderSRC <path>    Extra site overlay source folder
  --templateSiteFolderDST <path>    Overlay destination (default: <MKDocsDir>)
  --headerNumbering                 Enable auto heading numbers (default: OFF for MkDocs)
  --no-headerNumbering              Force-disable auto heading numbers
  --generatePDF                     Generate PDF per TM
  --pdfHeaderNote <text>            PDF page header text
  --pdfArtifactLink <url>           Optional link shown on index page
  --help                            Print this help
`);
    process.exit(0);
}

const tmDirectory = parseOption(cliArgs, 'TMDirectory') ?? '.';
const outputDir = parseOption(cliArgs, 'outputDir');
const MKDocsDir = parseOption(cliArgs, 'MKDocsDir') ?? './build/mkdocs';
const MKDocsSiteDir = parseOption(cliArgs, 'MKDocsSiteDir') ?? './build/site-mkdocs';
const template = parseOption(cliArgs, 'template') ?? 'MKdocs';
const visibilityArg = parseOption(cliArgs, 'visibility');
const visibility: 'full' | 'public' = visibilityArg === 'public' ? 'public' : 'full';
const siteName = parseOption(cliArgs, 'siteName') ?? 'Threat Models';
const templateSiteFolderSRC = parseOption(cliArgs, 'templateSiteFolderSRC');
const templateSiteFolderDST = parseOption(cliArgs, 'templateSiteFolderDST');
// MkDocs default: no heading numbering (site TOC/navigation already provides structure).
const headerNumbering = parseFlag(cliArgs, 'headerNumbering') && !parseFlag(cliArgs, 'no-headerNumbering');
const generatePDF = parseFlag(cliArgs, 'generatePDF');
const pdfHeaderNote = parseOption(cliArgs, 'pdfHeaderNote') ?? 'Private and confidential';
const pdfArtifactLink = parseOption(cliArgs, 'pdfArtifactLink');

buildMkdocsSite(tmDirectory, outputDir, {
    MKDocsDir,
    MKDocsSiteDir,
    template,
    visibility,
    siteName,
    templateSiteFolderSRC,
    templateSiteFolderDST,
    headerNumbering,
    generatePDF,
    pdfHeaderNote,
    pdfArtifactLink,
});
