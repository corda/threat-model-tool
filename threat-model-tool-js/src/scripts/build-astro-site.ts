#!/usr/bin/env node
/**
 * build-astro-site.ts
 *
 * Discovers threat models in a directory, builds each one, then generates
 * an Astro Starlight documentation site wrapping them all.
 *
 * CLI usage:
 *   tsx src/scripts/build-astro-site.ts \
 *     --TMDirectory ./threatModels \
 *     --outputDir   ../build/site  \
 *     [--template MKdocs]          \
 *     [--visibility full|public]   \
 *     [--siteName "Threat Models"] \
 *     [--base /]                   \
 *     [--templateSiteFolderSRC ./myTemplate] \
 *     [--no-headerNumbering]       \
 *     [--generatePDF]              \
 *     [--pdfHeaderNote "text"]
 */

import path from 'path';
import fs from 'fs';
import { execSync } from 'child_process';
import { fileURLToPath } from 'url';
import yaml from 'js-yaml';
import { buildSingleTM, type BuildTMOptions } from './build-threat-model.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/** Resolve astro-site/ directory relative to this script (src/scripts/) */
function getAstroSiteDir(): string {
    // When running via tsx: this file is in src/scripts/
    // astro-site/ is at the same level as src/
    return path.resolve(__dirname, '..', '..', 'astro-site');
}

interface TMEntry {
    name: string;
    yamlPath: string;
    id: string;
    title: string;
}

/**
 * Light YAML parse — just extracts ID and title from a TM YAML file
 * without instantiating the full ThreatModel class.
 */
function extractTMMetadata(yamlPath: string): { id: string; title: string } {
    const content = fs.readFileSync(yamlPath, 'utf-8');
    const doc = yaml.load(content) as Record<string, any>;
    return {
        id: doc?.ID ?? path.basename(yamlPath, path.extname(yamlPath)),
        title: doc?.title ?? doc?.ID ?? path.basename(yamlPath, path.extname(yamlPath)),
    };
}

/**
 * Discover TMs following the <name>/<name>.yaml convention.
 */
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
        if (fs.existsSync(yamlPath)) {
            const meta = extractTMMetadata(yamlPath);
            tmList.push({
                name: entry.name,
                yamlPath,
                id: meta.id,
                title: meta.title,
            });
        }
    }

    tmList.sort((a, b) => a.name.localeCompare(b.name));
    return tmList;
}

/**
 * Copy a directory recursively, overwriting existing files.
 */
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

/**
 * Prepend Starlight-compatible YAML frontmatter to an MD file.
 */
function injectFrontmatter(mdPath: string, title: string): void {
    const content = fs.readFileSync(mdPath, 'utf-8');
    // If file already has frontmatter, skip
    if (content.trimStart().startsWith('---')) return;

    const frontmatter = [
        '---',
        `title: "${title.replace(/"/g, '\\"')}"`,
        '---',
        '',
    ].join('\n');

    fs.writeFileSync(mdPath, frontmatter + content, 'utf-8');
}

/**
 * Generate the Starlight index page listing all TMs.
 */
function generateIndexPage(tmList: TMEntry[], docsDir: string): void {
    const lines = [
        '---',
        'title: Threat Models Index',
        '---',
        '',
        '# Threat Models',
        '',
    ];

    for (const tm of tmList) {
        const slug = tm.name.toLowerCase();
        lines.push(`- [${tm.title} Threat Model](/${slug}/)`);
    }

    lines.push('');
    fs.writeFileSync(path.join(docsDir, 'index.mdx'), lines.join('\n'), 'utf-8');
}

/**
 * Generate the astro.config.mjs with dynamic sidebar entries.
 */
function generateAstroConfig(
    tmList: TMEntry[],
    astroSiteDir: string,
    options: {
        siteName: string;
        base: string;
        customCss: string[];
        extraSidebarEntries: Array<{ label: string; link: string }>;
        headScript: string[];
    }
): void {
    const sidebarEntries = [
        `        { label: 'Home', link: '/' },`,
        ...tmList.map(tm =>
            `        { label: '${tm.title.replace(/'/g, "\\'")}', link: '/${tm.name.toLowerCase()}/' },`
        ),
        ...options.extraSidebarEntries.map(e =>
            `        { label: '${e.label.replace(/'/g, "\\'")}', link: '${e.link}' },`
        ),
    ].join('\n');

    // Build a JSON array of nav links for the top bar script
    const navLinks = [
        { label: 'Home', href: '/' },
        ...tmList.map(tm => ({ label: tm.title, href: `/${tm.name.toLowerCase()}/` })),
        ...options.extraSidebarEntries.map(e => ({ label: e.label, href: e.link })),
    ];
    const navLinksJson = JSON.stringify(navLinks);

    const cssEntries = options.customCss
        .map(c => `        '${c}',`)
        .join('\n');

    const headEntries = options.headScript
        .map(s => `        { tag: 'script', attrs: { src: '${s}', defer: true } },`)
        .join('\n');

    const baseConfig = options.base !== '/'
        ? `\n  base: '${options.base}',`
        : '';

    const config = `// @ts-check
// AUTO-GENERATED by build-astro-site.ts — do not edit manually
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

export default defineConfig({${baseConfig}
  integrations: [
    starlight({
      title: '${options.siteName.replace(/'/g, "\\'")}',
      customCss: [
${cssEntries}
      ],
      sidebar: [
${sidebarEntries}
      ],
      head: [
${headEntries}
        { tag: 'script', content: 'window.__TM_NAV_LINKS__ = ${navLinksJson.replace(/'/g, "\\\'")}' },
      ],
    }),
  ],
  trailingSlash: 'always',
});
`;

    fs.writeFileSync(path.join(astroSiteDir, 'astro.config.mjs'), config, 'utf-8');
}

/**
 * Process template site folder overlay (--templateSiteFolderSRC).
 * Returns extra sidebar entries and extra CSS paths.
 */
function processTemplateSiteFolder(
    templateSrc: string,
    astroSiteDir: string
): { extraSidebarEntries: Array<{ label: string; link: string }>; extraCss: string[] } {
    const result: { extraSidebarEntries: Array<{ label: string; link: string }>; extraCss: string[] } = {
        extraSidebarEntries: [],
        extraCss: [],
    };

    if (!fs.existsSync(templateSrc)) {
        console.warn(`Template site folder not found: ${templateSrc}`);
        return result;
    }

    // Process docs/ subdirectory → extra pages
    const docsDir = path.join(templateSrc, 'docs');
    if (fs.existsSync(docsDir)) {
        processTemplateDocsDir(docsDir, astroSiteDir, result);
    }

    // Process public/ subdirectory → static assets
    const publicDir = path.join(templateSrc, 'public');
    if (fs.existsSync(publicDir)) {
        copyDirRecursive(publicDir, path.join(astroSiteDir, 'public'));
    }

    return result;
}

function processTemplateDocsDir(
    docsDir: string,
    astroSiteDir: string,
    result: { extraSidebarEntries: Array<{ label: string; link: string }>; extraCss: string[] }
): void {
    const starlightDocsDir = path.join(astroSiteDir, 'src', 'content', 'docs');
    const starlightStylesDir = path.join(astroSiteDir, 'src', 'styles');

    for (const entry of fs.readdirSync(docsDir, { withFileTypes: true })) {
        if (entry.isDirectory() && entry.name === 'css') {
            // CSS files → src/styles/
            const cssDir = path.join(docsDir, 'css');
            for (const cssFile of fs.readdirSync(cssDir)) {
                if (cssFile.endsWith('.css')) {
                    fs.mkdirSync(starlightStylesDir, { recursive: true });
                    fs.copyFileSync(
                        path.join(cssDir, cssFile),
                        path.join(starlightStylesDir, cssFile)
                    );
                    result.extraCss.push(`./src/styles/${cssFile}`);
                } else {
                    // Non-CSS assets in css/ dir (e.g. images) → public/css/
                    const pubCssDir = path.join(astroSiteDir, 'public', 'css');
                    fs.mkdirSync(pubCssDir, { recursive: true });
                    fs.copyFileSync(
                        path.join(cssDir, cssFile),
                        path.join(pubCssDir, cssFile)
                    );
                }
            }
        } else if (entry.isFile() && (entry.name.endsWith('.md') || entry.name.endsWith('.mdx'))) {
            // Extra markdown pages → src/content/docs/
            const destPath = path.join(starlightDocsDir, entry.name);
            let content = fs.readFileSync(path.join(docsDir, entry.name), 'utf-8');

            // Extract title from first heading if no frontmatter
            if (!content.trimStart().startsWith('---')) {
                const headingMatch = content.match(/^#\s+(.+)$/m);
                const pageTitle = headingMatch ? headingMatch[1].trim() : path.basename(entry.name, path.extname(entry.name));
                content = `---\ntitle: "${pageTitle.replace(/"/g, '\\"')}"\n---\n\n${content}`;
            }

            fs.writeFileSync(destPath, content, 'utf-8');

            // Add sidebar entry
            const slug = path.basename(entry.name, path.extname(entry.name));
            const headingMatch = content.match(/title:\s*"?(.+?)"?\s*$/m);
            const label = headingMatch ? headingMatch[1] : slug;
            result.extraSidebarEntries.push({ label, link: `/${slug}/` });
        }
    }
}

// ---------------------------------------------------------------------------
// Main orchestrator
// ---------------------------------------------------------------------------

export interface AstroSiteOptions extends BuildTMOptions {
    siteName?: string;
    base?: string;
    templateSiteFolderSRC?: string;
}

export function buildAstroSite(
    tmDirectory: string,
    outputDir: string = '../build/site',
    options: AstroSiteOptions = {}
): void {
    const {
        siteName = 'Threat Models',
        base = '/',
        templateSiteFolderSRC,
        template = 'MKdocs',
        ...tmOptions
    } = options;

    const astroSiteDir = getAstroSiteDir();
    const docsDir = path.join(astroSiteDir, 'src', 'content', 'docs');
    const publicDir = path.join(astroSiteDir, 'public');

    console.log(`\n${'='.repeat(60)}`);
    console.log('Building Astro Starlight documentation site');
    console.log(`Astro project : ${astroSiteDir}`);
    console.log(`TM Directory  : ${path.resolve(tmDirectory)}`);
    console.log(`Output        : ${path.resolve(outputDir)}`);
    console.log(`Site name     : ${siteName}`);
    console.log('='.repeat(60));

    // ----- Step 1: Discover TMs -----
    const tmList = discoverTMs(tmDirectory);
    if (tmList.length === 0) {
        console.warn('No threat models found. Aborting.');
        return;
    }
    console.log(`\nFound ${tmList.length} threat model(s):`);
    for (const tm of tmList) {
        console.log(`  - ${tm.name} (${tm.title})`);
    }

    // ----- Step 2: Clean previous staged content -----
    // Clean docs dir (except .gitkeep)
    if (fs.existsSync(docsDir)) {
        for (const f of fs.readdirSync(docsDir)) {
            if (f === '.gitkeep') continue;
            const fp = path.join(docsDir, f);
            fs.rmSync(fp, { recursive: true, force: true });
        }
    }
    fs.mkdirSync(docsDir, { recursive: true });

    // Clean TM-specific dirs in public/ (but keep js/ and .gitkeep)
    if (fs.existsSync(publicDir)) {
        for (const f of fs.readdirSync(publicDir)) {
            if (f === '.gitkeep' || f === 'js' || f === 'css') continue;
            const fp = path.join(publicDir, f);
            if (fs.statSync(fp).isDirectory()) {
                fs.rmSync(fp, { recursive: true, force: true });
            }
        }
    }

    // ----- Step 3: Build each TM and stage content -----
    const stagingDir = path.join(astroSiteDir, '.staging');
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

        // Copy MD to docs/<TM>/index.md with frontmatter
        const mdFile = path.join(tmStagingDir, `${tm.id}.md`);
        if (!fs.existsSync(mdFile)) {
            // Try with the name if id differs
            const altMdFile = path.join(tmStagingDir, `${tm.name}.md`);
            if (fs.existsSync(altMdFile)) {
                stageTM(altMdFile, tm, docsDir, publicDir, tmStagingDir);
            } else {
                console.warn(`No MD file found for ${tm.name}, skipping staging`);
            }
        } else {
            stageTM(mdFile, tm, docsDir, publicDir, tmStagingDir);
        }
    }

    // Clean staging
    fs.rmSync(stagingDir, { recursive: true, force: true });

    // ----- Step 4: Generate index page -----
    generateIndexPage(tmList, docsDir);
    console.log('\nGenerated index page');

    // ----- Step 5: Process template site folder -----
    let extraSidebarEntries: Array<{ label: string; link: string }> = [];
    let extraCss: string[] = [];

    if (templateSiteFolderSRC) {
        console.log(`\nProcessing template site folder: ${templateSiteFolderSRC}`);
        const templateResult = processTemplateSiteFolder(
            path.resolve(templateSiteFolderSRC),
            astroSiteDir
        );
        extraSidebarEntries = templateResult.extraSidebarEntries;
        extraCss = templateResult.extraCss;
    }

    // ----- Step 6: Generate Astro config -----
    const customCss = ['./src/styles/threatmodel.css', ...extraCss];
    generateAstroConfig(tmList, astroSiteDir, {
        siteName,
        base,
        customCss,
        extraSidebarEntries,
        headScript: ['/js/tm.js'],
    });
    console.log('Generated astro.config.mjs');

    // ----- Step 7: Install deps if needed -----
    const nodeModulesDir = path.join(astroSiteDir, 'node_modules');
    if (!fs.existsSync(nodeModulesDir) || !fs.existsSync(path.join(nodeModulesDir, 'astro'))) {
        console.log('\nInstalling Astro dependencies...');
        execSync('npm install', { cwd: astroSiteDir, stdio: 'inherit' });
    }

    // ----- Step 8: Build Astro site -----
    console.log('\nBuilding Astro site...');
    execSync('npx astro build', { cwd: astroSiteDir, stdio: 'inherit' });

    // ----- Step 9: Copy output -----
    const distDir = path.join(astroSiteDir, 'dist');
    const absOutputDir = path.resolve(outputDir);

    if (fs.existsSync(distDir)) {
        fs.mkdirSync(absOutputDir, { recursive: true });
        copyDirRecursive(distDir, absOutputDir);
        console.log(`\nSite built successfully → ${absOutputDir}`);
    } else {
        console.error('Astro build did not produce dist/ directory');
        process.exit(1);
    }

    console.log(`\n${'='.repeat(60)}`);
    console.log('Astro Starlight site generation complete!');
    console.log(`Open ${absOutputDir}/index.html to view the site.`);
    console.log('='.repeat(60));
}

/**
 * Stage a single TM's content into the Astro site structure.
 */
function stageTM(
    mdFile: string,
    tm: TMEntry,
    docsDir: string,
    publicDir: string,
    tmStagingDir: string
): void {
    // Starlight lowercases folder names to create URL slugs.
    // We must use the same casing for public/ assets so relative paths resolve correctly.
    // e.g. page at /example1/ references img/foo.svg → resolves to /example1/img/foo.svg
    const slug = tm.name.toLowerCase();

    // Create docs/<TM>/ and copy MD as index.md
    const tmDocsDir = path.join(docsDir, tm.name);
    fs.mkdirSync(tmDocsDir, { recursive: true });
    fs.copyFileSync(mdFile, path.join(tmDocsDir, 'index.md'));
    injectFrontmatter(
        path.join(tmDocsDir, 'index.md'),
        `${tm.title} Threat Model`
    );

    // Copy img/ to public/<slug>/img/ (preserves relative paths in MD)
    const imgSrc = path.join(tmStagingDir, 'img');
    if (fs.existsSync(imgSrc)) {
        const imgDest = path.join(publicDir, slug, 'img');
        copyDirRecursive(imgSrc, imgDest);
    }

    // Copy css/ to public/<slug>/css/ (for standalone HTML fallback)
    const cssSrc = path.join(tmStagingDir, 'css');
    if (fs.existsSync(cssSrc)) {
        const cssDest = path.join(publicDir, slug, 'css');
        copyDirRecursive(cssSrc, cssDest);
    }
}

// ---------------------------------------------------------------------------
// CLI argument parser
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// CLI entry point
// ---------------------------------------------------------------------------

const cliArgs = process.argv.slice(2);

if (parseFlag(cliArgs, 'help') || parseFlag(cliArgs, 'h')) {
    console.log(`
Usage: build-astro-site.ts [options]

Options:
  --TMDirectory <path>              Directory containing TM sub-folders (default: .)
  --outputDir   <path>              Output directory for the site (default: ../build/site)
  --template    <name>              Report template (default: MKdocs)
  --visibility  full|public         Content visibility (default: full)
  --siteName    <text>              Site title (default: "Threat Models")
  --base        <path>              Base URL path for deployment (default: /)
  --templateSiteFolderSRC <path>    Extra pages/CSS/assets to overlay
  --no-headerNumbering              Disable auto heading numbers
  --generatePDF                     Generate PDF per TM
  --pdfHeaderNote <text>            PDF page header text
  --help                            Print this help
`);
    process.exit(0);
}

const tmDirectory = parseOption(cliArgs, 'TMDirectory') ?? '.';
const outputDir = parseOption(cliArgs, 'outputDir') ?? '../build/site';
const template = parseOption(cliArgs, 'template') ?? 'MKdocs';
const visibilityArg = parseOption(cliArgs, 'visibility');
const visibility: 'full' | 'public' =
    visibilityArg === 'public' ? 'public' : 'full';
const siteName = parseOption(cliArgs, 'siteName') ?? 'Threat Models';
const base = parseOption(cliArgs, 'base') ?? '/';
const templateSiteFolderSRC = parseOption(cliArgs, 'templateSiteFolderSRC');
const headerNumbering = !parseFlag(cliArgs, 'no-headerNumbering');
const generatePDF = parseFlag(cliArgs, 'generatePDF');
const pdfHeaderNote = parseOption(cliArgs, 'pdfHeaderNote') ?? 'Private and confidential';

buildAstroSite(tmDirectory, outputDir, {
    siteName,
    base,
    templateSiteFolderSRC,
    template,
    visibility,
    headerNumbering,
    generatePDF,
    pdfHeaderNote,
});
