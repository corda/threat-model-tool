import { HeadingNumberer } from './HeadingNumberer.js';

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
 * Create object anchor hash for HTML links
 * Format: parent._id.object._id or just object._id
 */
export function createObjectAnchorHash(tmObject: any): string {
    if (tmObject.parent && tmObject.parent._id && tmObject.parent.constructor.name === 'ThreatModel') {
        return `${tmObject.parent._id}.${tmObject._id}`;
    }
    return tmObject._id;
}

/**
 * Create title anchor hash (just lowercase and replace spaces)
 */
export function createTitleAnchorHash(title: string): string {
    return title.toLowerCase().replace(/\s+/g, '-').replace(/[^\w-]/g, '');
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
    const numberer = HeadingNumberer.getInstance();
    let number = "";
    
    if (HeadingNumberer.isEnabled()) {
        number = numberer.getNumber(level);
        if (number) {
            number = number + " ";
        }
    }

    // Create anchor
    let anchor = "";
    if (tmObject) {
        anchor = tmObject.anchor || createObjectAnchorHash(tmObject);
    } else {
        anchor = createTitleAnchorHash(title);
    }

    // Build header
    const hashes = '#'.repeat(level);
    const skipTOCDiv = skipTOC ? "  <div class='skipTOC'></div>" : "";
    
    return `${hashes} ${number}${title}${skipTOCDiv} <a id='${anchor}'></a>\n`;
}

/**
 * Render nested markdown list from data structure
 */
export function renderNestedMarkdownList(
    data: any[],
    level: number = 0,
    firstIndent: string | null = null
): string {
    const lines: string[] = [];
    const indent = firstIndent !== null ? firstIndent : "  ".repeat(level);

    for (const item of data) {
        if (typeof item === 'string') {
            lines.push(`${indent}- ${item}`);
        } else if (Array.isArray(item)) {
            lines.push(renderNestedMarkdownList(item, level + 1, indent + "  "));
        } else if (typeof item === 'object') {
            for (const [key, value] of Object.entries(item)) {
                lines.push(`${indent}- **${key}:**`);
                if (Array.isArray(value)) {
                    lines.push(renderNestedMarkdownList(value, level + 1, indent + "  "));
                } else {
                    lines.push(`${indent}  ${value}`);
                }
            }
        }
    }

    return lines.join('\n');
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

/**
 * Page break marker
 */
export const PAGEBREAK = '<div class="pagebreak"></div>';
