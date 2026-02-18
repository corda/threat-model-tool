#!/usr/bin/env node
/**
 * build-hugo-site.ts
 *
 * Discovers threat models in a directory, builds each one, then generates
 * a Hugo documentation site wrapping them all.
 */

import path from 'path';
import fs from 'fs';
import { execSync } from 'child_process';
import { fileURLToPath } from 'url';
import yaml from 'js-yaml';
import { buildSingleTM, type BuildTMOptions } from './build-threat-model.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function getHugoSiteDir(): string {
    return path.resolve(__dirname, '..', '..', 'hugo-site');
}

interface TMEntry {
    name: string;
    slug: string;
    yamlPath: string;
    id: string;
    title: string;
}

function toSlug(value: string): string {
    return value
        .trim()
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-+|-+$/g, '') || 'tm';
}

function extractTMMetadata(yamlPath: string): { id: string; title: string } {
    const content = fs.readFileSync(yamlPath, 'utf-8');
    const doc = yaml.load(content) as Record<string, unknown>;
    const id = typeof doc?.ID === 'string' ? doc.ID : path.basename(yamlPath, path.extname(yamlPath));
    const title = typeof doc?.title === 'string' ? doc.title : id;
    return { id, title };
}

function discoverTMs(tmDirectory: string): TMEntry[] {
    const absDir = path.resolve(tmDirectory);
    if (!fs.existsSync(absDir)) {
        console.error(`TMDirectory not found: ${absDir}`);
        process.exit(1);
    }

    const entries = fs.readdirSync(absDir, { withFileTypes: true });
    const tmList: TMEntry[] = [];

    for (const entry of entries) {
        if (!entry.isDirectory()) continue;
        const yamlPath = path.join(absDir, entry.name, `${entry.name}.yaml`);
        if (!fs.existsSync(yamlPath)) continue;

        const meta = extractTMMetadata(yamlPath);
        tmList.push({
            name: entry.name,
            slug: toSlug(entry.name),
            yamlPath,
            id: meta.id,
            title: meta.title,
        });
    }

    tmList.sort((a, b) => a.name.localeCompare(b.name));
    return tmList;
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

function removeFirstHeading(content: string): string {
    return content.replace(/^([\s\S]*?)^#\s+[^\n]*\n/m, '$1');
}

function addFrontmatter(mdPath: string, title: string, weight?: number): void {
    let content = fs.readFileSync(mdPath, 'utf-8');
    content = removeFirstHeading(content);

    if (!content.trimStart().startsWith('---')) {
        const frontmatter = [
            '---',
            `title: "${title.replace(/"/g, '\\"')}"`,
            ...(typeof weight === 'number' ? [`weight: ${weight}`] : []),
            '---',
            '',
        ].join('\n');
        content = frontmatter + content;
    }

    fs.writeFileSync(mdPath, content, 'utf-8');
}

function generateDocsIndex(tmList: TMEntry[], docsDir: string): void {
    const lines = [
        '---',
        'title: "Threat Models Index"',
        'weight: 1',
        '---',
        '',
        '# Threat Models',
        '',
    ];

    for (const tm of tmList) {
        lines.push(`- [${tm.title} Threat Model](/docs/${tm.slug}/)`);
    }

    lines.push('');
    fs.writeFileSync(path.join(docsDir, '_index.md'), lines.join('\n'), 'utf-8');
}

function generateHugoConfig(
    hugoSiteDir: string,
    options: {
        siteName: string;
        baseURL: string;
    }
): void {
    const content = [
        `baseURL = "${options.baseURL.replace(/"/g, '\\"')}"`,
        `title = "${options.siteName.replace(/"/g, '\\"')}"`,
        'languageCode = "en-us"',
        'disableKinds = ["taxonomy", "term", "RSS", "sitemap", "robotsTXT"]',
        '',
        '[params]',
        '  showToc = false',
        '',
        '[markup]',
        '  [markup.goldmark]',
        '    [markup.goldmark.renderer]',
        '      unsafe = true',
        '',
    ].join('\n');

    fs.writeFileSync(path.join(hugoSiteDir, 'hugo.toml'), content, 'utf-8');
}

function walkFilesRecursive(root: string): string[] {
    const files: string[] = [];

    function walk(current: string): void {
        for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
            const fullPath = path.join(current, entry.name);
            if (entry.isDirectory()) {
                walk(fullPath);
            } else {
                files.push(fullPath);
            }
        }
    }

    if (fs.existsSync(root)) {
        walk(root);
    }

    return files;
}

function processTemplateSiteFolder(templateSrc: string, hugoSiteDir: string): void {
    if (!fs.existsSync(templateSrc)) {
        console.warn(`Template site folder not found: ${templateSrc}`);
        return;
    }

    const docsSource = path.join(templateSrc, 'docs');
    const docsDest = path.join(hugoSiteDir, 'content', 'docs');
    const staticDest = path.join(hugoSiteDir, 'static');

    if (fs.existsSync(docsSource)) {
        for (const file of walkFilesRecursive(docsSource)) {
            const relative = path.relative(docsSource, file);
            const ext = path.extname(file).toLowerCase();

            if (relative.startsWith(`css${path.sep}`) && ext === '.css') {
                const cssFileName = path.basename(relative);
                const cssDestDir = path.join(staticDest, 'css');
                fs.mkdirSync(cssDestDir, { recursive: true });
                fs.copyFileSync(file, path.join(cssDestDir, cssFileName));
                continue;
            }

            if (ext === '.md' || ext === '.mdx') {
                const relMd = relative.replace(/\.mdx$/i, '.md');
                const destPath = path.join(docsDest, relMd);
                fs.mkdirSync(path.dirname(destPath), { recursive: true });

                let content = fs.readFileSync(file, 'utf-8');
                if (!content.trimStart().startsWith('---')) {
                    const headingMatch = content.match(/^#\s+(.+)$/m);
                    const pageTitle = headingMatch
                        ? headingMatch[1].trim()
                        : path.basename(relMd, '.md');
                    content = `---\ntitle: "${pageTitle.replace(/"/g, '\\"')}"\n---\n\n${content}`;
                }

                fs.writeFileSync(destPath, content, 'utf-8');
            }
        }
    }

    const publicSource = path.join(templateSrc, 'public');
    if (fs.existsSync(publicSource)) {
        copyDirRecursive(publicSource, staticDest);
    }
}

function stageTM(mdFile: string, tm: TMEntry, docsDir: string, tmStagingDir: string, weight: number): void {
    const tmDocsDir = path.join(docsDir, tm.slug);
    fs.mkdirSync(tmDocsDir, { recursive: true });

    const tmDocPath = path.join(tmDocsDir, 'index.md');
    fs.copyFileSync(mdFile, tmDocPath);
    addFrontmatter(tmDocPath, `${tm.title} Threat Model`, weight);

    const imgSrc = path.join(tmStagingDir, 'img');
    if (fs.existsSync(imgSrc)) {
        copyDirRecursive(imgSrc, path.join(tmDocsDir, 'img'));
    }

    const cssSrc = path.join(tmStagingDir, 'css');
    if (fs.existsSync(cssSrc)) {
        copyDirRecursive(cssSrc, path.join(tmDocsDir, 'css'));
    }
}

export interface HugoSiteOptions extends BuildTMOptions {
    siteName?: string;
    baseURL?: string;
    templateSiteFolderSRC?: string;
}

export function buildHugoSite(
    tmDirectory: string,
    outputDir: string = '../build/site-hugo',
    options: HugoSiteOptions = {}
): void {
    const {
        siteName = 'Threat Models',
        baseURL = '/',
        templateSiteFolderSRC,
        template = 'MKdocs',
        ...tmOptions
    } = options;

    const hugoSiteDir = getHugoSiteDir();
    const docsDir = path.join(hugoSiteDir, 'content', 'docs');
    const stagingDir = path.join(hugoSiteDir, '.staging');
    const buildDir = path.join(hugoSiteDir, 'public-build');

    console.log(`\n${'='.repeat(60)}`);
    console.log('Building Hugo documentation site');
    console.log(`Hugo project  : ${hugoSiteDir}`);
    console.log(`TM Directory  : ${path.resolve(tmDirectory)}`);
    console.log(`Output        : ${path.resolve(outputDir)}`);
    console.log(`Site name     : ${siteName}`);
    console.log('='.repeat(60));

    const tmList = discoverTMs(tmDirectory);
    if (tmList.length === 0) {
        console.warn('No threat models found. Aborting.');
        return;
    }

    console.log(`\nFound ${tmList.length} threat model(s):`);
    for (const tm of tmList) {
        console.log(`  - ${tm.name} (${tm.title})`);
    }

    fs.mkdirSync(docsDir, { recursive: true });
    for (const entry of fs.readdirSync(docsDir, { withFileTypes: true })) {
        if (entry.name === '_index.md') continue;
        fs.rmSync(path.join(docsDir, entry.name), { recursive: true, force: true });
    }

    fs.mkdirSync(stagingDir, { recursive: true });

    let weight = 10;
    for (const tm of tmList) {
        console.log(`\n--- Building ${tm.name} ---`);

        const tmStagingDir = path.join(stagingDir, tm.slug);
        fs.mkdirSync(tmStagingDir, { recursive: true });

        try {
            buildSingleTM(tm.yamlPath, tmStagingDir, { ...tmOptions, template });
        } catch (err) {
            console.error(`ERROR building ${tm.name}: ${err}`);
            continue;
        }

        const mdFile = path.join(tmStagingDir, `${tm.id}.md`);
        if (fs.existsSync(mdFile)) {
            stageTM(mdFile, tm, docsDir, tmStagingDir, weight);
            weight += 10;
            continue;
        }

        const altMdFile = path.join(tmStagingDir, `${tm.name}.md`);
        if (fs.existsSync(altMdFile)) {
            stageTM(altMdFile, tm, docsDir, tmStagingDir, weight);
            weight += 10;
            continue;
        }

        console.warn(`No MD file found for ${tm.name}, skipping staging`);
    }

    fs.rmSync(stagingDir, { recursive: true, force: true });

    generateDocsIndex(tmList, docsDir);
    generateHugoConfig(hugoSiteDir, { siteName, baseURL });

    if (templateSiteFolderSRC) {
        console.log(`\nProcessing template site folder: ${templateSiteFolderSRC}`);
        processTemplateSiteFolder(path.resolve(templateSiteFolderSRC), hugoSiteDir);
    }

    const nodeModulesDir = path.join(hugoSiteDir, 'node_modules');
    if (!fs.existsSync(nodeModulesDir) || !fs.existsSync(path.join(nodeModulesDir, 'hugo-bin'))) {
        console.log('\nInstalling Hugo dependencies...');
        execSync('npm install', { cwd: hugoSiteDir, stdio: 'inherit' });
    }

    console.log('\nBuilding Hugo site...');
    execSync('npm run build -- --destination public-build --cleanDestinationDir', {
        cwd: hugoSiteDir,
        stdio: 'inherit',
    });

    const absOutputDir = path.resolve(outputDir);
    fs.mkdirSync(absOutputDir, { recursive: true });
    copyDirRecursive(buildDir, absOutputDir);

    console.log(`\nSite built successfully → ${absOutputDir}`);
    console.log(`\n${'='.repeat(60)}`);
    console.log('Hugo site generation complete!');
    console.log(`Open ${absOutputDir}/index.html to view the site.`);
    console.log('='.repeat(60));
}

function parseFlag(args: string[], flag: string): boolean {
    return args.includes(`--${flag}`);
}

function parseOption(args: string[], flag: string): string | undefined {
    const idx = args.indexOf(`--${flag}`);
    if (idx !== -1 && idx + 1 < args.length && !args[idx + 1].startsWith('--')) {
        return args[idx + 1];
    }
    return undefined;
}

const cliArgs = process.argv.slice(2);

if (parseFlag(cliArgs, 'help') || parseFlag(cliArgs, 'h')) {
    console.log(`
Usage: build-hugo-site.ts [options]

Options:
  --TMDirectory <path>              Directory containing TM sub-folders (default: .)
  --outputDir   <path>              Output directory for the site (default: ../build/site-hugo)
  --template    <name>              Report template (default: MKdocs)
  --visibility  full|public         Content visibility (default: full)
  --siteName    <text>              Site title (default: "Threat Models")
  --baseURL     <url>               Hugo baseURL (default: /)
  --base        <path>              Alias for --baseURL
  --templateSiteFolderSRC <path>    Extra pages/CSS/assets to overlay
  --no-headerNumbering              Disable auto heading numbers
  --generatePDF                     Generate PDF per TM
  --pdfHeaderNote <text>            PDF page header text
  --help                            Print this help
`);
    process.exit(0);
}

const tmDirectory = parseOption(cliArgs, 'TMDirectory') ?? '.';
const outputDir = parseOption(cliArgs, 'outputDir') ?? '../build/site-hugo';
const template = parseOption(cliArgs, 'template') ?? 'MKdocs';
const visibilityArg = parseOption(cliArgs, 'visibility');
const visibility: 'full' | 'public' = visibilityArg === 'public' ? 'public' : 'full';
const siteName = parseOption(cliArgs, 'siteName') ?? 'Threat Models';
const baseURL = parseOption(cliArgs, 'baseURL') ?? parseOption(cliArgs, 'base') ?? '/';
const templateSiteFolderSRC = parseOption(cliArgs, 'templateSiteFolderSRC');
const headerNumbering = !parseFlag(cliArgs, 'no-headerNumbering');
const generatePDF = parseFlag(cliArgs, 'generatePDF');
const pdfHeaderNote = parseOption(cliArgs, 'pdfHeaderNote') ?? 'Private and confidential';

buildHugoSite(tmDirectory, outputDir, {
    siteName,
    baseURL,
    templateSiteFolderSRC,
    template,
    visibility,
    headerNumbering,
    generatePDF,
    pdfHeaderNote,
});
