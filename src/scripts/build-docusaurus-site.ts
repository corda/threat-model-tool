#!/usr/bin/env node
/**
 * build-docusaurus-site.ts
 *
 * Discovers threat models in a directory, builds each one, then generates
 * a Docusaurus documentation site wrapping them all.
 *
 * CLI usage:
 *   tsx src/scripts/build-docusaurus-site.ts \
 *     --TMDirectory ./threatModels \
 *     --outputDir   ./build/site-docusaurus \
 *     [--template MKdocs] \
 *     [--visibility full|public] \
 *     [--siteName "Threat Models"] \
 *     [--base /] \
 *     [--templateSiteFolderSRC ./myTemplate] \
 *     [--no-headerNumbering] \
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

function getDocusaurusSiteDir(): string {
    return path.resolve(__dirname, '..', '..', 'docusaurus-site');
}

interface TMEntry {
    name: string;
    yamlPath: string;
    id: string;
    title: string;
    slug: string;
}

interface SidebarEntry {
    label: string;
    id: string;
    to: string;
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
    const idValue = typeof doc?.ID === 'string' ? doc.ID : path.basename(yamlPath, path.extname(yamlPath));
    const titleValue = typeof doc?.title === 'string' ? doc.title : idValue;
    return {
        id: idValue,
        title: titleValue,
    };
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
            yamlPath,
            id: meta.id,
            title: meta.title,
            slug: toSlug(entry.name),
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

function syncParentMkdocsCss(siteDir: string): void {
    const parentCssDir = path.resolve(__dirname, '..', '..', '..', 'src', 'r3threatmodeling', 'assets', 'css');
    const legacyCssDir = path.join(siteDir, 'src', 'css', 'legacy');
    fs.mkdirSync(legacyCssDir, { recursive: true });

    const filesToSync = ['tm.css', 'github.min.css'];
    for (const fileName of filesToSync) {
        const srcFile = path.join(parentCssDir, fileName);
        const destFile = path.join(legacyCssDir, fileName);
        if (fs.existsSync(srcFile)) {
            fs.copyFileSync(srcFile, destFile);
        } else {
            console.warn(`Parent CSS file not found: ${srcFile}`);
        }
    }
}

function removeFirstHeading(content: string): string {
    return content.replace(/^([\s\S]*?)^#\s+[^\n]*\n/m, '$1');
}

function balanceRowTag(row: string, tag: 'td' | 'th'): string {
    const openRegex = new RegExp(`<${tag}(?:\\s[^>]*)?>`, 'gi');
    const closeRegex = new RegExp(`</${tag}>`, 'gi');
    const openCount = (row.match(openRegex) ?? []).length;
    const closeCount = (row.match(closeRegex) ?? []).length;

    if (openCount <= closeCount) {
        return row;
    }

    const missing = openCount - closeCount;
    return row.replace(/<\/tr>/i, `${'</' + tag + '>'.repeat(missing)}</tr>`);
}

function normalizeHtmlTableRows(content: string): string {
    return content.replace(/<tr[\s\S]*?<\/tr>/gi, row => {
        let fixed = row;
        fixed = balanceRowTag(fixed, 'th');
        fixed = balanceRowTag(fixed, 'td');
        return fixed;
    });
}

function addFrontmatter(mdPath: string, title: string, slug: string): void {
    let content = fs.readFileSync(mdPath, 'utf-8');
    content = normalizeHtmlTableRows(content);
    content = removeFirstHeading(content);

    if (!content.trimStart().startsWith('---')) {
        const frontmatter = [
            '---',
            `title: "${title.replace(/"/g, '\\"')}"`,
            `slug: /${slug}/`,
            '---',
            '',
        ].join('\n');
        content = frontmatter + content;
    }

    fs.writeFileSync(mdPath, content, 'utf-8');
}

function generateHomeDoc(tmList: TMEntry[], docsDir: string): void {
    const lines = [
        '---',
        'title: Threat Models Index',
        'slug: /',
        '---',
        '',
        '# Threat Models',
        '',
    ];

    for (const tm of tmList) {
        lines.push(`- [${tm.title} Threat Model](/${tm.slug}/)`);
    }

    lines.push('');
    fs.writeFileSync(path.join(docsDir, 'index.md'), lines.join('\n'), 'utf-8');
}

function generateSidebarsFile(siteDir: string, tmList: TMEntry[], extraEntries: SidebarEntry[]): void {
    const tmDocs = tmList
        .map(tm => `    { type: 'doc', id: '${tm.name}/index', label: '${tm.title.replace(/'/g, "\\'")}' },`)
        .join('\n');

    const extraDocs = extraEntries
        .map(entry => `    { type: 'doc', id: '${entry.id}', label: '${entry.label.replace(/'/g, "\\'")}' },`)
        .join('\n');

    const content = `/** @type {import('@docusaurus/plugin-content-docs').SidebarsConfig} */
module.exports = {
  docs: [
    { type: 'doc', id: 'index', label: 'Home' },
${tmDocs}${tmDocs && extraDocs ? '\n' : ''}${extraDocs}
  ]
};
`;

    fs.writeFileSync(path.join(siteDir, 'sidebars.js'), content, 'utf-8');
}

function generateDocusaurusConfig(
    siteDir: string,
    tmList: TMEntry[],
    extraEntries: SidebarEntry[],
    options: { siteName: string; base: string }
): void {
    const navbarItems = [
        `        { to: '/', label: 'Home', position: 'left' },`,
        ...tmList.map(tm =>
            `        { to: '/${tm.slug}/', label: '${tm.title.replace(/'/g, "\\'")}', position: 'left' },`
        ),
        ...extraEntries.map(entry =>
            `        { to: '${entry.to}', label: '${entry.label.replace(/'/g, "\\'")}', position: 'left' },`
        ),
    ].join('\n');

    const config = `// AUTO-GENERATED by build-docusaurus-site.ts — do not edit manually

/** @type {import('@docusaurus/types').Config} */
module.exports = {
  title: '${options.siteName.replace(/'/g, "\\'")}',
  tagline: 'Generated threat model documentation',
  url: 'http://localhost',
  baseUrl: '${options.base}',
    markdown: {
        format: 'md',
        hooks: {
            onBrokenMarkdownLinks: 'warn'
        }
    },
  onBrokenLinks: 'warn',
  trailingSlash: true,
  presets: [
    [
      'classic',
      {
        docs: {
          path: 'docs',
          routeBasePath: '/',
          sidebarPath: require.resolve('./sidebars.js')
        },
        blog: false,
        pages: false,
        sitemap: false,
        theme: {
          customCss: require.resolve('./src/css/custom.css')
        }
      }
    ]
  ],
  themeConfig: {
    navbar: {
      title: '${options.siteName.replace(/'/g, "\\'")}',
      items: [
${navbarItems}
      ]
    }
  },
  scripts: [
    {
      src: '/js/tm.js',
      defer: true
    }
  ]
};
`;

    fs.writeFileSync(path.join(siteDir, 'docusaurus.config.cjs'), config, 'utf-8');
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

function processTemplateSiteFolder(
    templateSrc: string,
    siteDir: string
): { extraSidebarEntries: SidebarEntry[]; cssImports: string[] } {
    const result: { extraSidebarEntries: SidebarEntry[]; cssImports: string[] } = {
        extraSidebarEntries: [],
        cssImports: [],
    };

    if (!fs.existsSync(templateSrc)) {
        console.warn(`Template site folder not found: ${templateSrc}`);
        return result;
    }

    const docsSource = path.join(templateSrc, 'docs');
    const docsDest = path.join(siteDir, 'docs');

    if (fs.existsSync(docsSource)) {
        for (const file of walkFilesRecursive(docsSource)) {
            const relative = path.relative(docsSource, file);
            const ext = path.extname(file).toLowerCase();

            if (relative.startsWith(`css${path.sep}`) && ext === '.css') {
                const cssOutputDir = path.join(siteDir, 'src', 'css', 'template');
                fs.mkdirSync(cssOutputDir, { recursive: true });
                const cssFileName = relative.substring(4).replace(/[\\/]/g, '__');
                const cssDest = path.join(cssOutputDir, cssFileName);
                fs.copyFileSync(file, cssDest);
                result.cssImports.push(`@import './template/${cssFileName}';`);
                continue;
            }

            if (ext === '.md' || ext === '.mdx') {
                const destPath = path.join(docsDest, relative);
                fs.mkdirSync(path.dirname(destPath), { recursive: true });
                let content = fs.readFileSync(file, 'utf-8');
                if (!content.trimStart().startsWith('---')) {
                    const headingMatch = content.match(/^#\s+(.+)$/m);
                    const pageTitle = headingMatch
                        ? headingMatch[1].trim()
                        : path.basename(relative, ext);
                    const pageSlug = toSlug(path.basename(relative, ext));
                    content = `---\ntitle: "${pageTitle.replace(/"/g, '\\"')}"\nslug: /${pageSlug}/\n---\n\n${content}`;
                }
                fs.writeFileSync(destPath, content, 'utf-8');

                const id = relative.replace(/\\/g, '/').replace(/\.(md|mdx)$/i, '');
                const fileBaseName = path.basename(relative, ext);
                const label = fileBaseName === 'index'
                    ? path.basename(path.dirname(relative))
                    : fileBaseName;
                const to = `/${toSlug(fileBaseName === 'index' ? path.basename(path.dirname(relative)) : fileBaseName)}/`;
                result.extraSidebarEntries.push({ label, id, to });
            }
        }
    }

    const publicSource = path.join(templateSrc, 'public');
    if (fs.existsSync(publicSource)) {
        copyDirRecursive(publicSource, path.join(siteDir, 'static'));
    }

    return result;
}

function writeTemplateCssImports(siteDir: string, cssImports: string[]): void {
    const tmExtraPath = path.join(siteDir, 'src', 'css', 'tm-extra.css');
    const lines = [
        '/* Generated by build-docusaurus-site.ts */',
        ...cssImports,
        '',
    ];
    fs.writeFileSync(tmExtraPath, lines.join('\n'), 'utf-8');
}

function stageTM(
    mdFile: string,
    tm: TMEntry,
    docsDir: string,
    staticDir: string,
    tmStagingDir: string
): void {
    const tmDocsDir = path.join(docsDir, tm.name);
    fs.mkdirSync(tmDocsDir, { recursive: true });

    const tmDocPath = path.join(tmDocsDir, 'index.md');
    fs.copyFileSync(mdFile, tmDocPath);
    addFrontmatter(tmDocPath, `${tm.title} Threat Model`, tm.slug);

    const imgSrc = path.join(tmStagingDir, 'img');
    if (fs.existsSync(imgSrc)) {
        copyDirRecursive(imgSrc, path.join(tmDocsDir, 'img'));
        copyDirRecursive(imgSrc, path.join(staticDir, tm.slug, 'img'));
    }

    const cssSrc = path.join(tmStagingDir, 'css');
    if (fs.existsSync(cssSrc)) {
        copyDirRecursive(cssSrc, path.join(tmDocsDir, 'css'));
        copyDirRecursive(cssSrc, path.join(staticDir, tm.slug, 'css'));
    }
}

export interface DocusaurusSiteOptions extends BuildTMOptions {
    siteName?: string;
    base?: string;
    templateSiteFolderSRC?: string;
}

export function buildDocusaurusSite(
    tmDirectory: string,
    outputDir: string = './build/site-docusaurus',
    options: DocusaurusSiteOptions = {}
): void {
    const {
        siteName = 'Threat Models',
        base = '/',
        templateSiteFolderSRC,
        template = 'MKdocs',
        ...tmOptions
    } = options;

    const siteDir = getDocusaurusSiteDir();
    const docsDir = path.join(siteDir, 'docs');
    const staticDir = path.join(siteDir, 'static');

    syncParentMkdocsCss(siteDir);

    console.log(`\n${'='.repeat(60)}`);
    console.log('Building Docusaurus documentation site');
    console.log(`Docusaurus project : ${siteDir}`);
    console.log(`TM Directory       : ${path.resolve(tmDirectory)}`);
    console.log(`Output             : ${path.resolve(outputDir)}`);
    console.log(`Site name          : ${siteName}`);
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

    if (fs.existsSync(docsDir)) {
        for (const name of fs.readdirSync(docsDir)) {
            if (name === '.gitkeep') continue;
            fs.rmSync(path.join(docsDir, name), { recursive: true, force: true });
        }
    }
    fs.mkdirSync(docsDir, { recursive: true });

    if (fs.existsSync(staticDir)) {
        for (const name of fs.readdirSync(staticDir)) {
            if (name === '.gitkeep' || name === 'js') continue;
            fs.rmSync(path.join(staticDir, name), { recursive: true, force: true });
        }
    }

    const stagingDir = path.join(siteDir, '.staging');
    fs.mkdirSync(stagingDir, { recursive: true });

    for (const tm of tmList) {
        console.log(`\n--- Building ${tm.name} ---`);
        const tmStagingDir = path.join(stagingDir, tm.name);
        fs.mkdirSync(tmStagingDir, { recursive: true });

        try {
            buildSingleTM(tm.yamlPath, tmStagingDir, { ...tmOptions, template });
        } catch (err) {
            console.error(`ERROR building ${tm.name}: ${err}`);
            continue;
        }

        const mdFile = path.join(tmStagingDir, `${tm.id}.md`);
        if (fs.existsSync(mdFile)) {
            stageTM(mdFile, tm, docsDir, staticDir, tmStagingDir);
            continue;
        }

        const altMdFile = path.join(tmStagingDir, `${tm.name}.md`);
        if (fs.existsSync(altMdFile)) {
            stageTM(altMdFile, tm, docsDir, staticDir, tmStagingDir);
        } else {
            console.warn(`No MD file found for ${tm.name}, skipping staging`);
        }
    }

    fs.rmSync(stagingDir, { recursive: true, force: true });

    generateHomeDoc(tmList, docsDir);
    console.log('\nGenerated docs/index.md');

    let extraSidebarEntries: SidebarEntry[] = [];
    let cssImports: string[] = [];

    if (templateSiteFolderSRC) {
        console.log(`\nProcessing template site folder: ${templateSiteFolderSRC}`);
        const templateResult = processTemplateSiteFolder(path.resolve(templateSiteFolderSRC), siteDir);
        extraSidebarEntries = templateResult.extraSidebarEntries;
        cssImports = templateResult.cssImports;
    }

    writeTemplateCssImports(siteDir, cssImports);
    generateSidebarsFile(siteDir, tmList, extraSidebarEntries);
    generateDocusaurusConfig(siteDir, tmList, extraSidebarEntries, { siteName, base });
    console.log('Generated sidebars.js + docusaurus.config.cjs');

    const nodeModulesDir = path.join(siteDir, 'node_modules');
    if (!fs.existsSync(nodeModulesDir) || !fs.existsSync(path.join(nodeModulesDir, '@docusaurus', 'core'))) {
        console.log('\nInstalling Docusaurus dependencies...');
        execSync('npm install', { cwd: siteDir, stdio: 'inherit' });
    }

    console.log('\nBuilding Docusaurus site...');
    execSync('npm run build', { cwd: siteDir, stdio: 'inherit' });

    const buildDir = path.join(siteDir, 'build');
    const absOutputDir = path.resolve(outputDir);

    if (!fs.existsSync(buildDir)) {
        console.error('Docusaurus build did not produce build/ directory');
        process.exit(1);
    }

    fs.mkdirSync(absOutputDir, { recursive: true });
    copyDirRecursive(buildDir, absOutputDir);

    console.log(`\nSite built successfully → ${absOutputDir}`);
    console.log(`\n${'='.repeat(60)}`);
    console.log('Docusaurus site generation complete!');
    console.log(`Open ${absOutputDir}/index.html to view the site.`);
    console.log('='.repeat(60));
}

const cliArgs = process.argv.slice(2);

if (parseFlag(cliArgs, 'help') || parseFlag(cliArgs, 'h')) {
    console.log(`
Usage: build-docusaurus-site.ts [options]

Defaults: generated outputs are written under ./build/* unless overridden.

Options:
  --TMDirectory <path>              Directory containing TM sub-folders (default: .)
    --outputDir   <path>              Output directory for the site (default: ./build/site-docusaurus)
  --template    <name>              Report template (default: MKdocs)
  --visibility  full|public         Content visibility (default: full)
  --siteName    <text>              Site title (default: "Threat Models")
  --base        <path>              Base URL path for deployment (default: /)
  --templateSiteFolderSRC <path>    Extra pages/CSS/assets to overlay
  --no-headerNumbering              Disable auto heading numbers (default: ON)
  --generatePDF                     Generate PDF per TM
  --pdfHeaderNote <text>            PDF page header text
  --help                            Print this help
`);
    process.exit(0);
}

const tmDirectory = parseOption(cliArgs, 'TMDirectory') ?? '.';
const outputDir = parseOption(cliArgs, 'outputDir') ?? './build/site-docusaurus';
const template = parseOption(cliArgs, 'template') ?? 'MKdocs';
const visibilityArg = parseOption(cliArgs, 'visibility');
const visibility: 'full' | 'public' = visibilityArg === 'public' ? 'public' : 'full';
const siteName = parseOption(cliArgs, 'siteName') ?? 'Threat Models';
const base = parseOption(cliArgs, 'base') ?? '/';
const templateSiteFolderSRC = parseOption(cliArgs, 'templateSiteFolderSRC');
const headerNumbering = !parseFlag(cliArgs, 'no-headerNumbering');
const generatePDF = parseFlag(cliArgs, 'generatePDF');
const pdfHeaderNote = parseOption(cliArgs, 'pdfHeaderNote') ?? 'Private and confidential';

buildDocusaurusSite(tmDirectory, outputDir, {
    siteName,
    base,
    templateSiteFolderSRC,
    template,
    visibility,
    headerNumbering,
    generatePDF,
    pdfHeaderNote,
});
