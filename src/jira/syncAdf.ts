import type { AdfDocument, AdfNode } from './syncTypes.js';

const INLINE_TOKEN_RE = /\[([^\]]+)\]\(([^)]+)\)|\*\*([^*]+)\*\*|`([^`]+)`/g;
const ORDERED_RE = /^\d+\.\s+(.*)$/;
const BULLET_RE = /^-\s+(.*)$/;
const HEADING_RE = /^\*\*([^*]+)\*\*$/;

export function sanitizeDescriptionMarkdown(text: string): string {
    const lines = text.split(/\r?\n/);
    let i = 0;

    while (i < lines.length && !lines[i].trim()) {
        i += 1;
    }

    if (i < lines.length) {
        const first = lines[i].trim().toLowerCase();
        if (first === 'description' || first === 'description:' || first === '**description**' || first === '**description:**') {
            i += 1;
            while (i < lines.length && !lines[i].trim()) {
                i += 1;
            }
        }
    }

    const cleaned = lines.slice(i).join('\n').trim();
    return cleaned || text.trim();
}

export function parseInline(text: string): AdfNode[] {
    const nodes: AdfNode[] = [];
    let pos = 0;

    for (const match of text.matchAll(INLINE_TOKEN_RE)) {
        const start = match.index ?? 0;
        if (start > pos) {
            nodes.push({ type: 'text', text: text.slice(pos, start) });
        }

        if (match[1] && match[2]) {
            nodes.push({
                type: 'text',
                text: match[1],
                marks: [{ type: 'link', attrs: { href: match[2] } }],
            });
        } else if (match[3]) {
            nodes.push({ type: 'text', text: match[3], marks: [{ type: 'strong' }] });
        } else if (match[4]) {
            nodes.push({ type: 'text', text: match[4], marks: [{ type: 'code' }] });
        }

        pos = start + match[0].length;
    }

    if (pos < text.length) {
        nodes.push({ type: 'text', text: text.slice(pos) });
    }

    return nodes;
}

export function markdownToAdf(markdown: string): AdfDocument {
    const content: AdfNode[] = [];
    let paragraphLines: string[] = [];
    let listType: 'ordered' | 'bullet' | null = null;
    let listItems: string[] = [];

    const flushParagraph = () => {
        const joined = paragraphLines.map(line => line.trim()).filter(Boolean).join(' ').trim();
        if (joined) {
            content.push({ type: 'paragraph', content: parseInline(joined) });
        }
        paragraphLines = [];
    };

    const flushList = () => {
        if (!listType || listItems.length === 0) {
            listType = null;
            listItems = [];
            return;
        }

        content.push({
            type: listType === 'ordered' ? 'orderedList' : 'bulletList',
            content: listItems.map(item => ({
                type: 'listItem',
                content: [{ type: 'paragraph', content: parseInline(item.trim()) }],
            })),
        });

        listType = null;
        listItems = [];
    };

    for (const rawLine of markdown.split(/\r?\n/)) {
        const line = rawLine.replace(/\s+$/g, '');
        const trimmed = line.trim();

        if (!trimmed) {
            flushParagraph();
            flushList();
            continue;
        }

        if (trimmed === '---') {
            flushParagraph();
            flushList();
            content.push({ type: 'rule' });
            continue;
        }

        const heading = HEADING_RE.exec(trimmed);
        if (heading) {
            flushParagraph();
            flushList();
            content.push({ type: 'heading', attrs: { level: 3 }, content: parseInline(heading[1]) });
            continue;
        }

        const ordered = ORDERED_RE.exec(trimmed);
        const bullet = BULLET_RE.exec(trimmed);
        if (ordered || bullet) {
            flushParagraph();
            const nextType: 'ordered' | 'bullet' = ordered ? 'ordered' : 'bullet';
            if (listType && listType !== nextType) {
                flushList();
            }
            listType = nextType;
            listItems.push((ordered ?? bullet)?.[1] ?? '');
            continue;
        }

        if (listType && (line.startsWith('  ') || line.startsWith('\t')) && listItems.length > 0) {
            listItems[listItems.length - 1] = `${listItems[listItems.length - 1]} ${trimmed}`;
            continue;
        }

        if (listType) {
            flushList();
        }

        paragraphLines.push(trimmed);
    }

    flushParagraph();
    flushList();

    if (content.length === 0) {
        content.push({ type: 'paragraph', content: [{ type: 'text', text: ' ' }] });
    }

    return { type: 'doc', version: 1, content };
}

export function adfTextLines(node: unknown): string[] {
    const out: string[] = [];

    if (Array.isArray(node)) {
        for (const child of node) {
            out.push(...adfTextLines(child));
        }
        return out;
    }

    if (!node || typeof node !== 'object') {
        return out;
    }

    const value = node as { text?: unknown; content?: unknown };
    if (typeof value.text === 'string' && value.text.trim()) {
        out.push(value.text.trim());
    }
    if (Array.isArray(value.content)) {
        out.push(...adfTextLines(value.content));
    }

    return out;
}
