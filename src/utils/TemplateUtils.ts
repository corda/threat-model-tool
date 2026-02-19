/** Page break div matching Python's PAGEBREAK constant (no surrounding newlines) */
export const PAGEBREAK = '<div class="pagebreak"></div>';

/**
 * Safe property access with default value
 */
export function valueOr(obj: any, attr: string, alt: any): any {
    try {
        const value = obj[attr];
        return value !== undefined ? value : alt;
    } catch {
        return alt;
    }
}

/**
 * Create object anchor hash for HTML links.
 * Matches Python: return tmObject.anchor
 */
export function createObjectAnchorHash(tmObject: any): string {
    return tmObject.anchor;
}

/**
 * Create title anchor hash.
 * Matches Python: title.lower().rstrip().replace(' ','-').replace(':','')
 *                 .replace(',','').replace('`','').replace("'","")
 *                 then TAG_RE.sub('', hash)
 */
export function createTitleAnchorHash(title: string): string {
    let hash = title.toLowerCase().trimEnd()
        .replace(/ /g, '-')
        .replace(/:/g, '')
        .replace(/,/g, '')
        .replace(/`/g, '')
        .replace(/'/g, '');
    hash = hash.replace(/<[^>]+>/g, '');
    return hash;
}

/**
 * Create markdown header with anchor and optional numbering
 * Matches Python: makeMarkdownLinkedHeader(level, title, ctx, skipTOC, tmObject)
 */
export function makeMarkdownLinkedHeader(
    level: number,
    title: string,
    ctx: any = {},
    skipTOC: boolean = false,
    tmObject: any = null
): string {
    // Python currently disables eager numbering in makeMarkdownLinkedHeader()
    // and relies on a later report post-processing pass.
    const number = "";

    // Create anchor
    let anchor = "";
    if (tmObject) {
        anchor = tmObject.anchor || createObjectAnchorHash(tmObject);
    } else {
        anchor = createTitleAnchorHash(title);
    }

    // Build header — matches Python format exactly:
    //   code = "\n\n" + header + (" " + skip_html if skip_html else "") + " <a id='...'></a>\n"
    //   return "\n" + code + "\n"
    const hashes = '#'.repeat(level);
    const skipTOCHtml = skipTOC ? "  <span class='skipTOC'></span>" : "";
    const header = `${hashes} ${number}${title.trimEnd()}`;
    const code = `\n\n${header}${skipTOCHtml ? ' ' + skipTOCHtml : ''} <a id='${anchor}'></a>\n`;
    return `\n${code}\n`;
}

/**
 * Render nested markdown list from data structure.
 * Matches Python's renderNestedMarkdownList() which uses a stream-based approach
 * and handles both dicts (objects) and lists (arrays).
 */
export function renderNestedMarkdownList(
    data: any,
    level: number = 0,
    firstIndent: string | null = null
): string {
    const parts: string[] = [];
    _renderNested(data, level, parts, firstIndent);
    return parts.join('');
}

function _renderNested(
    data: any,
    level: number,
    parts: string[],
    firstIndent: string | null,
): void {
    const indent = "  ".repeat(Math.max(0, level));

    if (data && typeof data === 'object' && !Array.isArray(data)) {
        // Dict/object handler
        for (const [key, value] of Object.entries(data)) {
            if (parts.length === 0 && firstIndent !== null) {
                parts.push(`${firstIndent}${key}: `);
            } else {
                parts.push(`${indent}- **${key}**: `);
            }
            if (typeof value === 'object' && value !== null) {
                parts.push('\n');
                _renderNested(value, level + 1, parts, firstIndent);
            } else {
                parts.push(`${value}\n`);
            }
        }
    } else if (Array.isArray(data)) {
        // List/array handler
        for (const item of data) {
            if (typeof item === 'object' && !Array.isArray(item)) {
                _renderNested(item, level + 1, parts, firstIndent);
            } else if (Array.isArray(item)) {
                parts.push(`${indent}- \n`);
                _renderNested(item, level + 1, parts, firstIndent);
            } else {
                parts.push(`${indent}- ${item}\n`);
            }
        }
    }
}

/**
 * Strip markdown formatting from text
 */
export function unmark(text: string): string {
    if (!text) return "";
    
    // Remove markdown links [text](url) -> text
    text = text.replace(/\[([^\]]+)\]\([^\)]+\)/g, '$1');
    
    // Remove emphasis
    text = text.replace(/\*\*([^*]+)\*\*/g, '$1');
    text = text.replace(/\*([^*]+)\*/g, '$1');
    text = text.replace(/__([^_]+)__/g, '$1');
    text = text.replace(/_([^_]+)_/g, '$1');
    
    // Remove code
    text = text.replace(/`([^`]+)`/g, '$1');
    
    return text;
}

/**
 * Clean markdown text by removing links and references
 */
export function cleanMarkdownText(text: string): string {
    if (!text) return "";
    
    // Transform markdown links to text only
    text = text.replace(/\[([^\]]+)\]\([^\)]+\)/g, '$1');
    
    // Delete from "**Refs:" till end
    text = text.replace(/\*\*Refs?:.*$/s, '');
    
    return text;
}

