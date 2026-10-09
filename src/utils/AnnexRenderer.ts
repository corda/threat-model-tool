/**
 * Annex sections from markdown files.
 *
 * Turns a folder tree of markdown files (`<model>/assets/annexes/`) into numbered annex
 * sections at the end of the report. See docs/ANNEXES.md for the author-facing rules.
 *
 *   annexes/
 *     10-incident-response-plan/     -> "Annex N: Incident Response Plan"
 *       _index.md                    -> optional: annex title (its # heading) and intro
 *       00-plan.md                   -> a section, titled by its first # heading
 *       sub-folder/...               -> a nested heading, same rules
 *
 * What this module does to the markdown it reads:
 *   - shifts headings so each file's `#` title sits under its folder's heading
 *   - strips manual numbers ("## 3. Purpose") because the report numbers headings itself
 *   - rewrites relative links to other annex files into in-report anchors
 *   - embeds a linked `.puml` as an image and copies it where the PlantUML step renders it
 *   - warns about broken links and about `BACKTICKED_IDS` that the model does not define
 */
import fs from 'fs';
import path from 'path';
import { PAGEBREAK } from './TemplateUtils.js';

export interface AnnexOptions {
    /** `<model>/assets/annexes` */
    annexesDir: string;
    /** Report output folder. Diagrams and images are copied to `<outputDir>/img/annexes/...` */
    outputDir: string;
    /** Number shown on the first annex ("Annex 3: ...") */
    firstNumber: number;
    /** Markdown heading level of an annex heading */
    headerLevel: number;
    /** MkDocs templates use `{#id}` anchors, the others use `<a id='id'></a>` */
    useAttrListAnchors: boolean;
    /** IDs defined by the model. When given, backticked IDs outside this set produce a warning. */
    knownIds?: Set<string>;
    /** Anchors that exist in the report. A backticked ID that matches one becomes a link to it. */
    linkTargets?: Set<string>;
}

export interface AnnexResult {
    markdown: string;
    fileCount: number;
    /** Broken links and files that cannot be placed. */
    linkWarnings: string[];
    /** Backticked IDs that the model does not define. */
    idWarnings: string[];
}

interface AnnexNode {
    name: string;
    /** Path relative to the annexes folder, with `/` separators */
    rel: string;
    abs: string;
    isDir: boolean;
    children: AnnexNode[];
}

const ID_PATTERN = /`([A-Z][A-Z0-9_]{4,})`/g;
const LINK_PATTERN = /(!?)\[([^\]]*)\]\(([^)\s]+)(?:\s+"[^"]*")?\)/g;
const IMAGE_EXTENSIONS = ['.png', '.jpg', '.jpeg', '.gif', '.svg'];
const FENCE_PATTERN = /^\s*(```|~~~)/;
const HEADING_PATTERN = /^(#{1,6})\s+(.*?)\s*$/;
const MANUAL_NUMBER_PATTERN = /^\d{1,2}(\.\d{1,2})*\.?\s+/;
const SKIP_TOC = "<span class='skipTOC'></span>";

// ---------------------------------------------------------------------------
// Naming and ordering
// ---------------------------------------------------------------------------

/** "20-playbooks" -> "Playbooks", "ir_plan.md" -> "Ir plan". Mixed-case names are kept as written. */
export function displayName(fileOrFolderName: string): string {
    const stem = fileOrFolderName.replace(/\.md$/i, '').replace(/^\d+[-_.\s]+/, '');
    const words = stem.replace(/[-_]+/g, ' ').trim();
    if (words === words.toLowerCase()) {
        return words.charAt(0).toUpperCase() + words.slice(1);
    }
    return words;
}

function anchorFor(rel: string): string {
    const slug = rel.replace(/\.md$/i, '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
    return `annex-${slug}`;
}

/** Numeric prefixes sort numerically, the rest alphabetically. Files come before sub-folders. */
function sortNodes(a: AnnexNode, b: AnnexNode): number {
    if (a.isDir !== b.isDir) {
        return a.isDir ? 1 : -1;
    }
    return a.name.localeCompare(b.name, 'en', { numeric: true, sensitivity: 'base' });
}

function scan(abs: string, rel: string): AnnexNode[] {
    const nodes: AnnexNode[] = [];
    for (const entry of fs.readdirSync(abs, { withFileTypes: true })) {
        if (entry.name.startsWith('.') || entry.name.startsWith('_index.')) {
            continue;
        }
        const childAbs = path.join(abs, entry.name);
        const childRel = rel ? `${rel}/${entry.name}` : entry.name;
        if (entry.isDirectory()) {
            nodes.push({ name: entry.name, rel: childRel, abs: childAbs, isDir: true, children: scan(childAbs, childRel) });
        } else if (entry.isFile() && entry.name.toLowerCase().endsWith('.md')) {
            nodes.push({ name: entry.name, rel: childRel, abs: childAbs, isDir: false, children: [] });
        }
    }
    return nodes.sort(sortNodes);
}

function countFiles(nodes: AnnexNode[]): number {
    return nodes.reduce((sum, node) => sum + (node.isDir ? countFiles(node.children) : 1), 0);
}

function collectFiles(nodes: AnnexNode[]): AnnexNode[] {
    return nodes.flatMap(node => (node.isDir ? collectFiles(node.children) : [node]));
}

// ---------------------------------------------------------------------------
// Markdown handling
// ---------------------------------------------------------------------------

/** The text of the first `# ` heading outside code fences, or null. */
function firstTitle(markdown: string): string | null {
    let inFence = false;
    for (const line of markdown.split('\n')) {
        if (FENCE_PATTERN.test(line)) {
            inFence = !inFence;
        } else if (!inFence) {
            const match = line.match(HEADING_PATTERN);
            if (match && match[1].length === 1) {
                return match[2].trim();
            }
        }
    }
    return null;
}

class AnnexRenderer {
    readonly linkWarnings: string[] = [];
    readonly idWarnings: string[] = [];
    private readonly anchors = new Map<string, string>();
    private readonly copied = new Set<string>();

    constructor(private readonly options: AnnexOptions, files: AnnexNode[]) {
        for (const file of files) {
            this.anchors.set(file.rel, anchorFor(file.rel));
        }
    }

    heading(level: number, title: string, anchor: string): string {
        const hashes = '#'.repeat(Math.min(level, 6));
        const anchorMd = this.options.useAttrListAnchors ? `{#${anchor}}` : `<a id='${anchor}'></a>`;
        return `\n\n${hashes} ${title} ${anchorMd}\n\n`;
    }

    anchorOf(rel: string): string {
        return this.anchors.get(rel) ?? anchorFor(rel);
    }

    /**
     * Prepare one file's body: drop its title heading, shift the other headings, strip manual
     * numbers and rewrite links. `titleLevel` is the heading level the file's `#` title gets.
     */
    body(markdown: string, fileRel: string, titleLevel: number): string {
        const shift = titleLevel - 1;
        const out: string[] = [];
        let inFence = false;
        let titleDropped = false;
        const reportedIds = new Set<string>();

        for (const line of markdown.replace(/\r\n/g, '\n').split('\n')) {
            if (FENCE_PATTERN.test(line)) {
                inFence = !inFence;
                out.push(line);
                continue;
            }
            if (inFence) {
                out.push(line);
                continue;
            }

            const heading = line.match(HEADING_PATTERN);
            if (heading) {
                const level = heading[1].length;
                if (level === 1 && !titleDropped) {
                    titleDropped = true;
                    continue;
                }
                const text = heading[2].replace(MANUAL_NUMBER_PATTERN, '');
                out.push(`${'#'.repeat(Math.min(level + shift, 6))} ${text} ${SKIP_TOC}`);
                continue;
            }

            this.checkIds(line, fileRel, reportedIds);
            out.push(this.linkModelIds(this.rewriteLinks(line, fileRel)));
        }
        return out.join('\n').trim();
    }

    private checkIds(line: string, fileRel: string, reported: Set<string>): void {
        const known = this.options.knownIds;
        if (!known) {
            return;
        }
        for (const match of line.matchAll(ID_PATTERN)) {
            const id = match[1];
            if (!known.has(id) && !reported.has(id)) {
                reported.add(id);
                this.idWarnings.push(`annexes/${fileRel}: \`${id}\` is not an ID defined in the model`);
            }
        }
    }

    /** `ID` -> [`ID`](#ID) when the report has an anchor with that ID. Text already inside a link is left alone. */
    private linkModelIds(line: string): string {
        const targets = this.options.linkTargets;
        if (!targets) {
            return line;
        }
        return line.replace(ID_PATTERN, (whole, id: string, offset: number) => {
            const insideLink = line[offset - 1] === '[' && line.slice(offset + whole.length).startsWith('](');
            return targets.has(id) && !insideLink ? `[${whole}](#${id})` : whole;
        });
    }

    private rewriteLinks(line: string, fileRel: string): string {
        const trimmed = line.trim();
        return line.replace(LINK_PATTERN, (whole, bang: string, text: string, target: string) => {
            if (/^([a-z][a-z0-9+.-]*:|\/\/|#|\/)/i.test(target)) {
                return whole; // external link, in-page anchor or absolute path
            }
            const [targetPath] = target.split('#');
            const resolved = path.posix.normalize(path.posix.join(path.posix.dirname(fileRel), decodeURI(targetPath)));
            const extension = path.posix.extname(resolved).toLowerCase();

            if (extension === '.md') {
                const anchor = this.anchors.get(resolved);
                if (!anchor) {
                    this.linkWarnings.push(`annexes/${fileRel}: link to "${target}" does not match an annex file`);
                    return text;
                }
                return `[${text}](#${anchor})`; // a #fragment on the target is dropped
            }

            if (extension === '.puml' || IMAGE_EXTENSIONS.includes(extension)) {
                const source = path.join(this.options.annexesDir, resolved);
                if (resolved.startsWith('..') || !fs.existsSync(source)) {
                    this.linkWarnings.push(`annexes/${fileRel}: "${target}" does not exist`);
                    return whole;
                }
                const imagePath = this.copyToImages(resolved, source, extension);
                if (extension !== '.puml') {
                    return `${bang}[${text}](${imagePath})`;
                }
                // A diagram link becomes the diagram; alone on its line it gets its own paragraph.
                const diagram = `![${text}](${imagePath})`;
                return !bang && trimmed === whole ? `\n${diagram}\n` : diagram;
            }
            return whole;
        });
    }

    /** Copy a diagram or image under `img/annexes/` and return its report-relative path. */
    private copyToImages(resolved: string, source: string, extension: string): string {
        const destinationRel = `img/annexes/${resolved}`;
        if (!this.copied.has(resolved)) {
            this.copied.add(resolved);
            const destination = path.join(this.options.outputDir, destinationRel);
            fs.mkdirSync(path.dirname(destination), { recursive: true });
            fs.copyFileSync(source, destination);
        }
        // The PlantUML step renders `x.puml` to `x.svg` next to it.
        return extension === '.puml' ? destinationRel.replace(/\.puml$/i, '.svg') : destinationRel;
    }
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

/** Render the annexes folder to markdown. Returns an empty result when it holds no annex. */
export function renderAnnexFolder(options: AnnexOptions): AnnexResult {
    const tree = scan(options.annexesDir, '');
    const empty: AnnexResult = { markdown: '', fileCount: 0, linkWarnings: [], idWarnings: [] };
    if (tree.length === 0) {
        return empty;
    }

    const rootFiles = tree.filter(node => !node.isDir);
    const annexes = tree.filter(node => node.isDir && countFiles(node.children) > 0);
    const renderer = new AnnexRenderer(options, collectFiles(annexes));
    for (const file of rootFiles) {
        renderer.linkWarnings.push(`annexes/${file.rel}: files must be inside an annex folder, so it is skipped`);
    }

    const lines: string[] = [];
    annexes.forEach((annex, index) => {
        const label = `Annex ${options.firstNumber + index}`;
        lines.push(PAGEBREAK);
        renderFolder(annex, options.headerLevel, `${label}: `, renderer, options, lines);
    });

    return {
        markdown: lines.join('\n'),
        fileCount: annexes.reduce((sum, annex) => sum + countFiles(annex.children), 0),
        linkWarnings: renderer.linkWarnings,
        idWarnings: renderer.idWarnings,
    };
}

function renderFolder(
    folder: AnnexNode,
    level: number,
    titlePrefix: string,
    renderer: AnnexRenderer,
    options: AnnexOptions,
    lines: string[]
): void {
    const indexPath = ['_index.md', '_index.markdown'].map(name => path.join(folder.abs, name)).find(fs.existsSync);
    const indexMarkdown = indexPath ? fs.readFileSync(indexPath, 'utf8') : '';
    const title = firstTitle(indexMarkdown) ?? displayName(folder.name);

    lines.push(renderer.heading(level, `${titlePrefix}${title}`, renderer.anchorOf(folder.rel)));
    if (indexMarkdown) {
        lines.push(renderer.body(indexMarkdown, `${folder.rel}/_index.md`, level + 1));
    }

    for (const child of folder.children) {
        if (child.isDir) {
            if (countFiles(child.children) > 0) {
                renderFolder(child, level + 1, '', renderer, options, lines);
            }
            continue;
        }
        const markdown = fs.readFileSync(child.abs, 'utf8');
        const fileTitle = firstTitle(markdown) ?? displayName(child.name);
        lines.push(PAGEBREAK);
        lines.push(renderer.heading(level + 1, fileTitle, renderer.anchorOf(child.rel)));
        lines.push(renderer.body(markdown, child.rel, level + 1));
    }
}

/** IDs defined in the given model files (`ID: NAME` entries), used to check backticked IDs. */
export function collectModelIds(yamlFiles: string[]): Set<string> {
    const ids = new Set<string>();
    for (const file of yamlFiles) {
        if (!fs.existsSync(file)) {
            continue;
        }
        for (const match of fs.readFileSync(file, 'utf8').matchAll(/^\s*-?\s*(?:REF)?ID:\s*['"]?([A-Za-z0-9_]+)/gm)) {
            ids.add(match[1]);
        }
    }
    return ids;
}

/** Anchors present in a generated report: `<a id='X'>`, `id="X"`, `name='X'` and MkDocs `{#X}`. */
export function collectAnchors(markdown: string): Set<string> {
    const anchors = new Set<string>();
    for (const match of markdown.matchAll(/(?:\bid|\bname)=['"]([A-Za-z0-9_.-]+)['"]|\{#([A-Za-z0-9_.-]+)\}/g)) {
        anchors.add(match[1] ?? match[2]);
    }
    return anchors;
}
