/**
 * Jira description formatting utilities.
 * Ports the Python threat_description, risk_description and treatment_plan functions.
 *
 * Two output formats:
 *   • wiki     – Jira wiki markup (Server/Data Center, REST API v2)
 *   • markdown – Standard Markdown (Jira Cloud CSV import, REST API v3)
 */

import type Threat from '../models/Threat.js';
import type Countermeasure from '../models/Countermeasure.js';
import type BaseThreatModelObject from '../models/BaseThreatModelObject.js';

export type DescriptionFormat = 'wiki' | 'markdown';

// ── Shared helpers ──────────────────────────────────────────────────────────

/** Countermeasures not yet in place (gaps to address). */
function resolveCountermeasures(threat: Threat): Countermeasure[] {
    const missing: Countermeasure[] = [];
    for (const cm of threat.countermeasures) {
        const resolved = (cm as any).resolve ? (cm as any).resolve() : cm;
        if (resolved && resolved.inPlace === false) {
            missing.push(resolved);
        }
    }
    return missing;
}

/** Countermeasures already in place (verify they are still effective). */
function resolveInPlaceCountermeasures(threat: Threat): Countermeasure[] {
    const inPlace: Countermeasure[] = [];
    for (const cm of threat.countermeasures) {
        const resolved = (cm as any).resolve ? (cm as any).resolve() : cm;
        if (resolved && resolved.inPlace === true) {
            inPlace.push(resolved);
        }
    }
    return inPlace;
}

function parentTitle(threat: Threat): string {
    const p = threat.parent as BaseThreatModelObject | null;
    return p?.title ?? 'Unknown';
}

// ── Wiki-markup helpers ─────────────────────────────────────────────────────

function panelMD(type?: string): string {
    switch (type) {
        case 'info':    return '{panel:bgColor=#deebff}';
        case 'warning': return '{panel:bgColor=#fefae6}';
        case 'error':   return '{panel:bgColor=#ffebe6}';
        case 'note':    return '{panel:bgColor=#eae6ff}';
        case 'success': return '{panel:bgColor=#e3fcef}';
        default:        return '{panel}';
    }
}

function secObjLinesWiki(threat: Threat): string {
    return threat.impactedSecObjs
        .map(so => {
            const resolved = (so as any).resolve ? (so as any).resolve() : so;
            return resolved?.shortText ? `** ${resolved.shortText()}` : `** ${so.REFIDValue}`;
        })
        .join('\n');
}

/**
 * Convert Jira-wiki h-tags (h1. h2. …) to markdown # if requested.
 */
function hashify(text: string, useHashes: boolean): string {
    if (!useHashes) return text;
    return text.replace(/h(\d)\.\s/g, (_match, level) => '#'.repeat(Number(level)) + ' ');
}

// ── Markdown helpers ────────────────────────────────────────────────────────

function secObjLinesMarkdown(threat: Threat): string {
    return threat.impactedSecObjs
        .map(so => {
            const resolved = (so as any).resolve ? (so as any).resolve() : so;
            return resolved?.shortText ? `  - ${resolved.shortText()}` : `  - ${so.REFIDValue}`;
        })
        .join('\n');
}

// ═══════════════════════════════════════════════════════════════════════════
// Wiki-markup descriptions (Jira Server / Data Center / REST API v2)
// ═══════════════════════════════════════════════════════════════════════════

export function treatmentPlanWiki(threat: Threat, tmHome = 'https://example.com'): string {
    const secobs = secObjLinesWiki(threat);
    const pTitle = parentTitle(threat);
    return (
        `h4. Required Actions\n\n` +
        `# Update the design document for ${pTitle} to describe how the threat will be mitigated.\n` +
        `Alternatively provide a statement as to why the threat is not applicable, or is an accepted risk.\n` +
        `# Ensure that the design clearly references the threat title and ID.\n` +
        `# Ensure that the following Security Objectives are referenced by the design:\n${secobs}\n` +
        `# Update this ticket with the location of the changes.\n` +
        `# Refer to the Security Issue Handling policy for more information.\n`
    );
}

export function threatDescriptionWiki(threat: Threat, hashes = true, tmHome = 'https://example.com'): string {
    const pTitle = parentTitle(threat);
    const refuri = `[${threat.id}|${tmHome}/${(threat as any).uri ?? threat.anchor}]\n${threat.title}`;

    const missing = resolveCountermeasures(threat);
    const inPlace = resolveInPlaceCountermeasures(threat);
    const mitgs = missing
        .map(cm => `# ${cm.title}\n${(cm.description ?? '').trim()}`)
        .join('\n');
    const existing = inPlace
        .map(cm => `# ${cm.title}\n${(cm.description ?? '').trim()}`)
        .join('\n');

    const secobs = secObjLinesWiki(threat);

    const existingSection = inPlace.length > 0
        ? `h4. Existing Controls\nThe following controls are already in place. Verify they are still effective:\n\n${existing}\n\n`
        : '';

    const desc =
        `This issue represents a design issue in the ${pTitle} design. ` +
        `Please ensure that the design is updated to detail how the threat will be mitigated.\n` +
        `h4. Threat Reference\n${panelMD('error')}${refuri}${panelMD()}\n\n` +
        `h4. Threat Description\n${threat.attack}\n\n` +
        existingSection +
        `h4. Suggested Countermeasures\n` +
        `The following countermeasures are potential solutions to mitigate the described threat:\n\n${mitgs}\n\n` +
        `h4. Acceptance Criteria\n\n` +
        `# Each suggested countermeasure below is either implemented or explicitly accepted as a risk.\n` +
        `# Existing controls have been verified as still effective.\n` +
        `# Evidence has been provided (e.g. code reference, PR, test result, config, audit record, or description of what was done).\n` +
        `# This ticket is updated with the evidence before closing.\n\n` +
        `h4. Required Actions\n\n` +
        `# Update the design document for ${pTitle} to describe how the threat will be mitigated.\n` +
        `Alternatively provide a statement as to why the threat is not applicable, or is an accepted risk.\n` +
        `# Ensure that the design clearly references the threat title and ID.\n` +
        `# Ensure that the following Security Objectives are referenced by the design:\n${secobs}\n` +
        `# Refer to the Security Issue Handling policy for more information.\n` +
        `\n\n`;

    return hashify(desc, hashes);
}

export function riskDescriptionWiki(threat: Threat, hashes = true, tmHome = 'https://example.com'): string {
    const pTitle = parentTitle(threat);
    const refuri = `[${threat.id}|${tmHome}/${(threat as any).uri ?? threat.anchor}]\n(${threat.title})`;

    const missing = resolveCountermeasures(threat);
    const inPlace = resolveInPlaceCountermeasures(threat);
    const mitgs = missing
        .map(cm => `# ${cm.title}\n${(cm.description ?? '').trim()}`)
        .join('\n');
    const existing = inPlace
        .map(cm => `# ${cm.title}\n${(cm.description ?? '').trim()}`)
        .join('\n');

    const existingSection = inPlace.length > 0
        ? `*Existing Controls*\nThe following controls are already in place. Verify they are still effective:\n\n${existing}\n\n`
        : '';

    const desc =
        `${threat.attack}\n\n` +
        `\n` +
        `${panelMD('error')}\n` +
        `*Threat Model Reference*\n` +
        `This risk represents a potential threat identified in the ${pTitle} threat model:\n\n` +
        `${refuri}${panelMD()}\n\n` +
        existingSection +
        `*Suggested Countermeasures*\n` +
        `The following mitigations are potential solutions to address the described threat:\n\n${mitgs}\n\n` +
        `*Acceptance Criteria*\n\n` +
        `# Each suggested countermeasure is either implemented or explicitly accepted as a risk.\n` +
        `# Existing controls have been verified as still effective.\n` +
        `# Evidence has been provided (e.g. code reference, PR, test result, config, audit record, or description of what was done).\n` +
        `# This ticket is updated with the evidence before closing.\n\n` +
        `*Required Actions*\n\n` +
        `# Review the risk and update the risk Likelihood and/or Impact.\n` +
        `# Consider the suggested countermeasures and update the treatment plan if applicable.\n` +
        `# Adjust the Target Date for Closure according to the Asset and Risk Methodology policy document.\n` +
        `\n\n`;

    return hashify(desc, hashes);
}

// ═══════════════════════════════════════════════════════════════════════════
// Markdown descriptions (Jira Cloud CSV import / REST API v3)
// ═══════════════════════════════════════════════════════════════════════════

export function threatDescriptionMarkdown(threat: Threat, tmHome = 'https://example.com'): string {
    const pTitle = parentTitle(threat);
    const ref = `[${threat.id}](${tmHome}/${(threat as any).uri ?? threat.anchor})`;

    const missing = resolveCountermeasures(threat);
    const inPlace = resolveInPlaceCountermeasures(threat);
    const mitgs = missing
        .map((cm, i) => `${i + 1}. **${cm.title}**\n   ${(cm.description ?? '').trim()}`)
        .join('\n');
    const existing = inPlace
        .map((cm, i) => `${i + 1}. **${cm.title}**\n   ${(cm.description ?? '').trim()}`)
        .join('\n');

    const secobs = secObjLinesMarkdown(threat);

    const existingSection = inPlace.length > 0
        ? `#### Existing Controls\n\nThe following controls are already in place. Verify they are still effective:\n\n${existing}\n\n`
        : '';

    return (
        `This issue represents a design issue in the ${pTitle} design. ` +
        `Please ensure that the design is updated to detail how the threat will be mitigated.\n\n` +
        `#### Threat Reference\n\n` +
        `> ${ref}\n> ${threat.title}\n\n` +
        `#### Threat Description\n\n${threat.attack}\n\n` +
        existingSection +
        `#### Suggested Countermeasures\n\n` +
        `The following countermeasures are potential solutions to mitigate the described threat:\n\n${mitgs}\n\n` +
        `#### Acceptance Criteria\n\n` +
        `1. Each suggested countermeasure is either implemented or explicitly accepted as a risk.\n` +
        `2. Existing controls have been verified as still effective.\n` +
        `3. Evidence has been provided (e.g. code reference, PR, test result, config, audit record, or description of what was done).\n` +
        `4. This ticket is updated with the evidence before closing.\n\n` +
        `#### Required Actions\n\n` +
        `1. Update the design document for ${pTitle} to describe how the threat will be mitigated.\n` +
        `   Alternatively provide a statement as to why the threat is not applicable, or is an accepted risk.\n` +
        `2. Ensure that the design clearly references the threat title and ID.\n` +
        `3. Ensure that the following Security Objectives are referenced by the design:\n${secobs}\n` +
        `4. Refer to the Security Issue Handling policy for more information.\n`
    );
}

export function riskDescriptionMarkdown(threat: Threat, tmHome = 'https://example.com'): string {
    const pTitle = parentTitle(threat);
    const ref = `[${threat.id}](${tmHome}/${(threat as any).uri ?? threat.anchor})`;

    const missing = resolveCountermeasures(threat);
    const inPlace = resolveInPlaceCountermeasures(threat);
    const mitgs = missing
        .map((cm, i) => `${i + 1}. **${cm.title}**\n   ${(cm.description ?? '').trim()}`)
        .join('\n');
    const existing = inPlace
        .map((cm, i) => `${i + 1}. **${cm.title}**\n   ${(cm.description ?? '').trim()}`)
        .join('\n');

    const existingSection = inPlace.length > 0
        ? `**Existing Controls**\n\nThe following controls are already in place. Verify they are still effective:\n\n${existing}\n\n`
        : '';

    return (
        `${threat.attack}\n\n` +
        `---\n\n` +
        `> **Threat Model Reference**\n` +
        `> This risk represents a potential threat identified in the ${pTitle} threat model:\n` +
        `>\n` +
        `> ${ref}\n> *(${threat.title})*\n\n` +
        existingSection +
        `**Suggested Countermeasures**\n\n` +
        `The following mitigations are potential solutions to address the described threat:\n\n${mitgs}\n\n` +
        `**Acceptance Criteria**\n\n` +
        `1. Each suggested countermeasure is either implemented or explicitly accepted as a risk.\n` +
        `2. Existing controls have been verified as still effective.\n` +
        `3. Evidence has been provided (e.g. code reference, PR, test result, config, audit record, or description of what was done).\n` +
        `4. This ticket is updated with the evidence before closing.\n\n` +
        `**Required Actions**\n\n` +
        `1. Review the risk and update the risk Likelihood and/or Impact.\n` +
        `2. Consider the suggested countermeasures and update the treatment plan if applicable.\n` +
        `3. Adjust the Target Date for Closure according to the Asset and Risk Methodology policy document.\n`
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// CSV-specific compact description (Jira Cloud CSV import)
// ═══════════════════════════════════════════════════════════════════════════

export function csvDescriptionMarkdown(threat: Threat, linkPrefix?: string): string {
    const missing = resolveCountermeasures(threat);
    const inPlace = resolveInPlaceCountermeasures(threat);
    const mitgs = missing
        .map((cm, i) => `${i + 1}. **${cm.title}**\n   ${(cm.description ?? '').trim()}`)
        .join('\n');
    const existing = inPlace
        .map((cm, i) => `${i + 1}. **${cm.title}**\n   ${(cm.description ?? '').trim()}`)
        .join('\n');

    const sections: string[] = [];

    // Start with threat narrative directly (Jira UI already labels this field as Description).
    const attackText = (threat.attack ?? '').trim();
    if (attackText) {
        sections.push(attackText);
    }

    // Impact (raw impactDesc without HTML/secObj appendages)
    const rawImpact = (threat as any).impactDesc as string | undefined;
    if (rawImpact) {
        sections.push(`**Impact**\n\n${rawImpact.trim()}`);
    }

    // Existing controls
    if (inPlace.length > 0) {
        sections.push(`**Existing Controls**\n\nThe following controls are already in place. Verify they are still effective:\n\n${existing}`);
    }

    // Suggested countermeasures
    if (missing.length > 0) {
        sections.push(`**Suggested Countermeasures**\n\n${mitgs}`);
    }

    // Acceptance criteria
    sections.push(
        `**Acceptance Criteria**\n\n` +
        `1. Each suggested countermeasure is either implemented or explicitly accepted as a risk.\n` +
        `2. Existing controls have been verified as still effective.\n` +
        `3. Evidence has been provided (e.g. code reference, PR, test result, config, audit record, or description of what was done).\n` +
        `4. This ticket is updated with the evidence before closing.`
    );

    // Reference link
    if (linkPrefix) {
        const link = `${linkPrefix}#${threat.id}`;
        sections.push(`**Reference**\n\n[${threat.id} — ${threat.title}](${link})`);
    }

    return sections.join('\n\n---\n\n') + '\n';
}

// ═══════════════════════════════════════════════════════════════════════════
// Format-aware dispatchers
// ═══════════════════════════════════════════════════════════════════════════

/** Backward-compatible aliases */
export const treatmentPlan = treatmentPlanWiki;
export const threatDescription = threatDescriptionWiki;
export const riskDescription = riskDescriptionWiki;

/** Pick the right formatter based on the requested format. */
export function riskDescriptionFormatted(threat: Threat, format: DescriptionFormat, tmHome = 'https://example.com'): string {
    return format === 'markdown'
        ? riskDescriptionMarkdown(threat, tmHome)
        : riskDescriptionWiki(threat, false, tmHome);
}

export function threatDescriptionFormatted(threat: Threat, format: DescriptionFormat, tmHome = 'https://example.com'): string {
    return format === 'markdown'
        ? threatDescriptionMarkdown(threat, tmHome)
        : threatDescriptionWiki(threat, false, tmHome);
}

export function mapCvssToImpact(severity: string): string {
    const map: Record<string, string> = {
        Critical: '5 - Very High',
        High:     '4 - High',
        Medium:   '3 - Medium',
        Low:      '2 - Low',
        None:     '1 - Very Low',
    };
    return map[severity] ?? 'None';
}

export function mapCvssToPriority(severity: string): string {
    const map: Record<string, string> = {
        Critical: 'Highest',
        High:     'High',
        Medium:   'Medium',
        Low:      'Low',
        None:     'Lowest',
    };
    return map[severity] ?? 'Medium';
}

export function riskRating(severity: string, likelihood: number): number {
    const map: Record<string, number> = {
        Critical: 5,
        High: 4,
        Medium: 3,
        Low: 2,
        None: 1,
    };
    return (map[severity] ?? 1) * likelihood;
}

export function treatmentPlanDate(rr: number): Date {
    const d = new Date();
    if (rr <= 5)        { d.setMonth(d.getMonth() + 2); }
    else if (rr <= 10)  { d.setMonth(d.getMonth() + 1); }
    else if (rr <= 16)  { d.setDate(d.getDate() + 14); }
    else                { d.setDate(d.getDate() + 7); }
    return d;
}

/** Format date as d/Mon/YYYY (no leading zero on day), matching the Python version. */
export function formatJiraDate(d: Date): string {
    const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
    return `${d.getDate()}/${months[d.getMonth()]}/${d.getFullYear()}`;
}
