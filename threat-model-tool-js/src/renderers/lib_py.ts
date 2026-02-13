import ThreatModel from '../models/ThreatModel.js';
import Threat from '../models/Threat.js';
import Countermeasure from '../models/Countermeasure.js';
import { makeMarkdownLinkedHeader, PAGEBREAK, createObjectAnchorHash, renderNestedMarkdownList } from '../utils/TemplateUtils.js';
import * as html from 'html-escaper';

function trueOrFalseMark(value: boolean): string {
    return value ? '<span style="color:green;">&#10004;</span>' : '&#10060;';
}

/**
 * Render grouped security objectives as a tree list.
 * Python reference: render_text_security_objectives_tree()
 */
function renderTextSecurityObjectivesTree(securityObjectives: any[]): string {
    const out: string[] = [];
    let current: string | null = null;
    for (const so of securityObjectives) {
        if (current !== so.group) {
            if (current !== null) {
                out.push('');
            }
            current = so.group;
            out.push(`**${current}:**\n`);
        }
        out.push(`- <a href="#${so.anchor}">${so.title}</a>\n`);
    }
    return out.join('\n');
}

/**
 * Render executive summary section
 * Python reference: executive_summary()
 */
export function executiveSummary(tmo: ThreatModel, headerLevel: number = 1, ctx: any = {}): string {
    const unmitNoOp = tmo.getThreatsByFullyMitigatedAndOperational(false, false);
    
    const lines: string[] = [];
    
    lines.push(makeMarkdownLinkedHeader(headerLevel + 1, 'Executive Summary', ctx, false));
    lines.push('> This section contains an executive summary of the threats and their mitigation status.\n');

    if (unmitNoOp.length < 1) {
        lines.push('**No unmitigated threats without operational countermeasures were identified**');
    } else {
        lines.push(`There are **${unmitNoOp.length}** unmitigated threats without proposed operational controls.<br/>`);
        lines.push('<div markdown="1">');
        lines.push('<table markdown="block" style="print-color-adjust: exact; -webkit-print-color-adjust: exact;">');
        lines.push('<tr><th>Threat ID</th><th>Severity</th></tr>');
        
        for (const threat of unmitNoOp) {
            const anchor = createObjectAnchorHash(threat);
            const cvssColor = threat.getSmartScoreColor();
            const cvssDesc = threat.getSmartScoreDesc();
            const parentId = (threat.parent as any)?._id || '';
            
            const cvssTd = `<td style="background-color: ${cvssColor}; " > <span markdown="block" style="font-weight:bold; color:white;"><strong>${cvssDesc}</strong></span> </td>`;
            
            let row = '<tr markdown="block"><td>';
            row += `<a href="#${anchor}">${parentId}.<br/>${threat.id}</a>`;
            
            // Proposal flag
            if ((threat as any).proposal || (threat as any).threatModel?.proposal) {
                row += '<br/><b>PROPOSAL (TBC) </b>';
            }
            
            if (threat.ticketLink) {
                row += `<br/><a href="${html.escape(threat.ticketLink)}"> Ticket link  </a>`;
            }
            
            row += `${cvssTd}</tr>`;
            lines.push(row);
        }
        
        lines.push('</table>');
        lines.push('</div>');
    }

    return lines.join('\n');
}

/**
 * Render threats summary table
 * Python reference: threats_summary()
 */
export function threatsSummary(tmo: ThreatModel, headerLevel: number = 1, ctx: any = {}): string {
    const mitigated = tmo.getThreatsByFullyMitigated(true);
    const unmit = tmo.getThreatsByFullyMitigated(false);
    const unmitNoOp = tmo.getThreatsByFullyMitigatedAndOperational(false, false);
    const allCount = tmo.getAllDown(Threat).length;
    
    const lines: string[] = [];
    lines.push(makeMarkdownLinkedHeader(headerLevel + 1, 'Threats Summary', ctx, false));

    if (mitigated.length < 1 && unmit.length < 1) {
        lines.push('**No threat identified or listed **');
    } else {
        lines.push(
            `There are a total of **${allCount}** identified threats of which **${unmit.length}** are not fully mitigated ` +
            `by default, and  **${unmitNoOp.length}** are unmitigated without proposed operational controls.<br/>`
        );
        lines.push('<div markdown="1">');
        lines.push('<table markdown="block" style="print-color-adjust: exact; -webkit-print-color-adjust: exact;">');
        lines.push('<tr><th>Threat ID</th><th>CVSS</th><th>Mitigation Status</th></tr>');

        for (const threat of [...unmit, ...mitigated]) {
            const anchor = createObjectAnchorHash(threat);
            const parentId = (threat.parent as any)?._id || '';
            const cvssColor = threat.getSmartScoreColor();
            const cvssDesc = threat.getSmartScoreDesc();
            const statusDesc = threat.statusDefaultText();
            const statusFill = threat.statusColors().fill;
            
            const proposal = ((threat as any).proposal || (threat as any).threatModel?.proposal)
                ? '<br/><b>FROM PROPOSAL / TBC</b>' : '';
            const ticket = threat.ticketLink
                ? `<br/><a href="${html.escape(threat.ticketLink)}"> Ticket link  </a>` : '';
            
            const cvssTd = `<td style="background-color: ${cvssColor}; " ><span markdown="block" style="font-weight:bold; color:white;"><strong>${cvssDesc}</strong></span></td>`;
            
            lines.push(
                `<tr markdown="block"><td>` +
                `<a href="#${anchor}">${parentId}.<br/>${threat.id}</a>${proposal}${ticket}` +
                `</td>${cvssTd}<td style="background-color: ${statusFill};text-align: center ">${statusDesc}</td>` +
                `</tr>`
            );
        }
        
        lines.push('</table></div>');
    }
    return lines.join('\n');
}

/**
 * Render a single countermeasure block
 * Python reference: render_countermeasure()
 */
function renderCountermeasure(cm: Countermeasure): string {
    const lines: string[] = [];
    
    if (cm.isReference) {
        lines.push(`<strong>Reference to <code>${cm.id}</code> ${cm.title}</strong><br/>`);
    } else {
        lines.push(`<strong> <code>${(cm as any)._id || cm.id}</code> ${cm.title}</strong><br/>`);
    }
    
    if ((cm as any).appliesToVersions) {
        lines.push(`<dt>Applies To Versions</dt><dd markdown="block">${html.escape((cm as any).appliesToVersions)}</dd>`);
    }
    
    lines.push(`<dd markdown="block">${cm.description}</dd>`);
    
    if ((cm as any).mitigationType) {
        lines.push(`<dd markdown="block"><strong>Mitigation type:</strong>${(cm as any).mitigationType}</dd>`);
    }
    
    const ip = trueOrFalseMark(cm.inPlace);
    const parentThreat = cm.parent as any;
    
    if (parentThreat?.fullyMitigated && !cm.inPlace) {
        lines.push(`<dd markdown="block"><strong>Countermeasure in place?</strong> ${ip} (not chosen as threat is mitigated by other countermeasures)</dd>`);
    } else {
        lines.push(`<dd markdown="block"><strong>Countermeasure in place?</strong> ${ip}</dd>`);
    }
    
    let op = '';
    if ((cm as any).operational) {
        const opMark = '<span style="color:green;">&#10004;</span>';
        const operator = (cm as any).operator ? ` (operated by ${(cm as any).operator})` : '';
        op = ` <strong>Is operational?</strong>${opMark}${operator}`;
    }
    lines.push(`${op}</dd>`);
    
    return lines.join('\n');
}

/**
 * Render a single threat block with full detail
 * Python reference: render_threat()
 */
function renderThreat(threat: Threat, headerLevel: number = 1, ctx: any = {}): string {
    const lines: string[] = [];
    const cssClass = (threat as any).proposal ? 'proposal' : 'current';
    
    lines.push(`<div markdown="1" class='${cssClass}'>`);
    
    // Anchor and legacy heading
    lines.push(`<a id="${(threat as any)._id || threat.id}"></a>`);
    
    const titleWithCode = `${threat.title} (<code>${(threat as any)._id || threat.id}</code>)`;
    lines.push(makeMarkdownLinkedHeader(headerLevel + 2, titleWithCode, ctx, false, threat));
    
    if ((threat as any).proposal) {
        lines.push(`From proposal: ${(threat as any).proposal}`);
    }
    
    // Per-threat SVG diagram
    lines.push('<div style="text-align: center;">');
    lines.push(`<img src="img/threatTree/${(threat as any)._id || threat.id}.svg"/>`);
    lines.push('</div>');
    
    // Definition list details
    lines.push('<dl markdown="block">');
    
    if ((threat as any).appliesToVersions) {
        lines.push('<dt>Applies To Versions</dt>');
        lines.push(`<dd markdown="block">${html.escape((threat as any).appliesToVersions)}</dd>`);
    }
    
    // Assets
    const assetRefs = (threat as any).assets || [];
    if (assetRefs.length > 0) {
        lines.push('<dt>Assets (IDs) involved in this threat:</dt>');
        for (const assetRef of assetRefs) {
            const asset = assetRef.resolve ? assetRef.resolve() : assetRef;
            if (asset) {
                lines.push(`<dd markdown="block"> - <code><a href="#${asset.anchor}">${asset._id || asset.id}</a></code> - ${asset.title}</dd>`);
            }
        }
    }
    
    // Attackers
    const attackerRefs = (threat as any).attackers || [];
    if (attackerRefs.length > 0) {
        lines.push('<dt>Threat actors:</dt>');
        for (const attackerRef of attackerRefs) {
            const attacker = attackerRef.resolve ? attackerRef.resolve() : attackerRef;
            if (attacker) {
                lines.push(`<dd markdown="block"> - <code><a href="#${attacker.anchor}">${attacker._id || attacker.id}</a></code></dd>`);
            }
        }
    }
    
    // Status
    const status = threat.statusDefaultText();
    lines.push(`<dt>Threat Status:</dt><dd markdown="block">${status}</dd>`);
    
    // Conditional
    if ((threat as any).conditional) {
        lines.push(`<dt>Threat condition:</dt><dd markdown="block">${(threat as any).conditional}</dd>`);
    }
    
    // Description / Attack — Python uses just the raw attack text
    lines.push(`<dt>Threat Description</dt><dd markdown="block">${(threat as any).attack ?? ''}</dd>`);
    
    // Impact (uses the impact_desc getter which resolves impactedSecObjs)
    if (threat.impact_desc !== undefined) {
        lines.push(`<dt>Impact</dt><dd markdown="block">${threat.impact_desc}</dd>`);
    }
    
    // Attack type
    if ((threat as any).attackType) {
        lines.push('<dt>Attack type</dt>');
        lines.push(`<dd markdown="block">${(threat as any).attackType}</dd>`);
    }
    
    // CVSS — only show when there's a real score (not TODO)
    if (threat.cvssObject && !threat.cvssObject.isTodo()) {
        const cvss = threat.cvssObject;
        lines.push('<dt>CVSS</dt>');
        lines.push(
            '<dd>\n' +
            `<strong>${cvss.getSmartScoreType()}:</strong> ${cvss.getSmartScoreDesc()} <br/>\n` +
            `<strong>Vector:</strong><code>${cvss.clean_vector()}</code>\n` +
            '</dd>'
        );
    }
    
    // Compliance — Python: renderNestedMarkdownList(threat.compliance, -1, firstIndent=None)
    // compliance can be a dict (object) or array
    if ((threat as any).compliance) {
        const complianceData = (threat as any).compliance;
        lines.push('Compliance:\n' + renderNestedMarkdownList(complianceData, -1, null));
    }
    
    lines.push('</dl>');
    
    // Ticket link
    if (threat.ticketLink) {
        const safe = html.escape(threat.ticketLink);
        lines.push(`<dt><strong>Ticket link:</strong><a href="${safe}"> ${safe}  </a> </dt><dd markdown="block"></dd>`);
    }
    
    // Countermeasures
    const cms = threat.countermeasures || [];
    if (cms.length > 0) {
        lines.push(makeMarkdownLinkedHeader(headerLevel + 3, `Counter-measures for ${(threat as any)._id || threat.id} `, ctx, true));
        lines.push('<dl markdown="block">');
        for (const cm of cms) {
            lines.push(renderCountermeasure(cm));
        }
        lines.push('</dl>');
    } else {
        lines.push('<i>No countermeasure listed</i>');
    }
    
    lines.push('</div>');
    return lines.join('\n');
}

/**
 * Render a single security objective
 * Python reference: render_security_objective()
 */
function renderSecurityObjective(so: any, headerLevel: number = 1, ctx: any = {}): string {
    const title = `${so.title} (<code>${so._id || so.id}</code>)`;
    const lines: string[] = [];
    lines.push(makeMarkdownLinkedHeader(headerLevel + 3, title, ctx, false, so));
    
    if (so.proposal) {
        lines.push(`From proposal: ${so.proposal}<br/>`);
    }
    if (so.inScope === false) {
        lines.push('(Not in scope)<br/>');
    }
    if (so.icon) {
        lines.push(`<img src="${so.icon}"/><br/>`);
    }
    lines.push(so.description);
    lines.push(`**Priority:** ${so.priority}\n`);
    
    if (so.contributesTo && so.contributesTo.length > 0) {
        lines.push('**Contributes to:**\n');
        for (const c of so.contributesTo) {
            if (typeof c.contributedToMDText === 'function') {
                lines.push(`- ${c.contributedToMDText()}\n`);
            } else {
                const resolved = c.resolve ? c.resolve() : c;
                if (resolved) {
                    lines.push(`- <code><a href="#${resolved.anchor}">${resolved.id}</a></code> *(${resolved.title})*\n`);
                }
            }
        }
    }
    
    if (so.treeImage) {
        lines.push('**Attack tree:**\n');
        lines.push(`<img src="img/secObjectives/${so._id || so.id}.svg"/>`);
        lines.push('<img src="img/legend_SecObjTree.svg" width="400"/>');
    }
    lines.push('<hr/>');
    return lines.join('\n');
}

/**
 * Render security objectives section
 * Python reference: render_tm_report_part() security objectives block
 */
export function renderSecurityObjectives(tmo: ThreatModel, headerLevel: number = 2, ctx: any = {}): string {
    const lines: string[] = [];
    
    lines.push(makeMarkdownLinkedHeader(headerLevel, `${tmo.title} security objectives`, ctx));
    lines.push(renderTextSecurityObjectivesTree(tmo.securityObjectives));
    
    // Diagram only for root
    if (tmo.parent === null) {
        lines.push('**Diagram:**\n<img src="img/secObjectives.svg"/>');
    }
    lines.push('**Details:**');
    
    // Sort by title like Python does
    const sorted = [...tmo.securityObjectives].sort((a, b) => a.title.localeCompare(b.title));
    for (const so of sorted) {
        lines.push(renderSecurityObjective(so, headerLevel - 2, ctx));
    }

    return lines.join('\n');
}

/**
 * Render linked threat models section
 * Python reference: render_tm_report_part() linked models block
 */
export function renderLinkedThreatModels(tmo: ThreatModel, headerLevel: number = 2, ctx: any = {}): string {
    const lines: string[] = [];
    const descendants = tmo.getDescendantsTM();
    
    if (descendants.length > 0) {
        lines.push(makeMarkdownLinkedHeader(headerLevel, 'Linked threat Models', ctx));
        for (const ltm of descendants) {
            // Python uses ltm.id which is the full hierarchical ID
            lines.push(`- **${ltm.title}** (ID: ${(ltm as any).getHierarchicalId ? (ltm as any).getHierarchicalId() : ltm.id})`);
        }
    }
    
    return lines.join('\n');
}

/**
 * Render a single attacker
 * Python reference: render_attacker()
 */
function renderAttacker(attacker: any, headerLevel: number = 1, ctx: any = {}): string {
    const title = `${attacker.title} (<code>${attacker._id || attacker.id}</code>)`;
    const lines: string[] = [];
    
    lines.push(`<a id="${attacker._id || attacker.id}"></a>`);
    lines.push(`**${title}**\n`);
    lines.push('<dl markdown="block">');
    lines.push(`<dt>Description:</dt><dd markdown="block">${attacker.description}</dd>`);
    
    if (attacker.reference) {
        lines.push(`<dt>Reference:</dt><dd>${html.escape(attacker.reference)}</dd>`);
    }
    lines.push(`<dt>In Scope as threat actor:</dt><dd>${attacker.inScope ? 'Yes' : 'No'}</dd>`);
    lines.push('</dl>');
    
    if (attacker.icon) {
        lines.push(`<img src="${attacker.icon}"/>`);
    }
    lines.push('<hr/>');
    return lines.join('\n');
}

/**
 * Render attackers section
 * Python reference: render_tm_report_part() attackers block
 */
export function renderAttackers(tmo: ThreatModel, headerLevel: number = 2, ctx: any = {}): string {
    const lines: string[] = [];
    
    lines.push(PAGEBREAK);
    lines.push(makeMarkdownLinkedHeader(headerLevel, `${tmo.title} Threat Actors`, ctx));
    lines.push('> Actors, agents, users and attackers may be used as synonymous.\n');
    
    for (const attacker of tmo.attackers) {
        lines.push(renderAttacker(attacker, headerLevel - 2, ctx));
    }
    
    return lines.join('\n');
}

/**
 * Render assumptions section
 * Python reference: render_tm_report_part() assumptions block
 */
export function renderAssumptions(tmo: ThreatModel, headerLevel: number = 2, ctx: any = {}): string {
    const lines: string[] = [];
    if (tmo.assumptions.length > 0) {
        lines.push(makeMarkdownLinkedHeader(headerLevel, 'Assumptions', ctx));
        for (const a of tmo.assumptions) {
            lines.push(`<dl markdown="block"><dt>${(a as any)._id || a.id}</dt><dd>${a.description} </dd></dl>`);
        }
    }
    return lines.join('\n');
}

/**
 * Render asset summary table
 * Python reference: render_asset_table()
 */
function renderAssetTable(assets: any[]): string {
    const sorted = [...assets].sort((a, b) => {
        // Sort by inScope descending (in-scope first)
        if (a.inScope !== b.inScope) return a.inScope ? -1 : 1;
        return 0;
    });
    
    const lines: string[] = [];
    lines.push('<table markdown="block">');
    lines.push('<tr><th>Title(ID)</th><th>Type</th><th>In Scope</th></tr>');
    
    for (const a of sorted) {
        const check = a.inScope ? '&#x2714;&#xFE0F;' : '&#x274C;';
        lines.push(
            `<tr markdown="block"><td markdown="block">${a.title}<br/><code><strong markdown="block">${a._id || a.id}</strong></code>` +
            `</td><td>${a.type}</td><td>${check}</td></tr>`
        );
    }
    lines.push('</table>');
    return lines.join('\n');
}

/**
 * Render a single asset detail block
 * Python reference: render_asset()
 */
function renderAssetDetail(asset: any, headerLevel: number = 1, ctx: any = {}, tmo: ThreatModel | null = null): string {
    const css = asset.proposal ? 'proposal' : 'current';
    const inScopeStr = asset.inScope ? 'in scope' : 'not in scope';
    const title = `${asset.title} (${asset.type} ${inScopeStr} - ID: <code>${asset._id || asset.id}</code>)`;
    
    const lines: string[] = [];
    lines.push(`<hr/>\n<div markdown="1" class='${css}'>`);
    
    if (asset.proposal) {
        lines.push(`From proposal: ${asset.proposal}`);
    }
    // Python uses asset.id (full hierarchical ID) for the anchor tag
    const hierarchicalId = asset.getHierarchicalId ? asset.getHierarchicalId() : asset.id;
    lines.push(`<a id="${hierarchicalId}"></a>`);
    lines.push(`**${title}**\n`);
    lines.push('<dl markdown="block">');
    
    if (asset.icon) {
        lines.push(`<img src="${asset.icon}"/><br/>`);
    }
    lines.push(asset.description);
    
    if (asset.appliesToVersions) {
        lines.push('<dt>Applies To Versions</dt>');
        lines.push(`<dd markdown="block">${html.escape(asset.appliesToVersions)}</dd>`);
    }
    if (asset.properties && Object.keys(asset.properties).length > 0) {
        lines.push('<dt markdown="block">Other properties</dt>');
        lines.push(`<dd markdown="block">${asset.propertiesHTML()}</dd>`);
    }
    if (asset.authentication) {
        lines.push('<dt>Authentication</dt>');
        lines.push(`<dd markdown="block">${asset.authentication}</dd>`);
    }
    if (asset.specifies && tmo) {
        const root = tmo.getRoot ? tmo.getRoot() : tmo;
        // Try to find the specified object
        const specified = root.getDescendantById ? root.getDescendantById(asset.specifies) : null;
        if (specified) {
            lines.push('<dt>Specifies, inherit analysis and attribute from:</dt>');
            lines.push(`<dd markdown="block"> ${specified.title}  (<a href="#${specified.anchor}">${specified._id}</a>) </dd>`);
        }
    }
    
    lines.push('</dl>\n</div>');
    return lines.join('\n');
}

/**
 * Render assets section
 * Python reference: render_tm_report_part() assets block
 */
export function renderAssets(tmo: ThreatModel, headerLevel: number = 2, ctx: any = {}): string {
    const lines: string[] = [];
    if (tmo.assets.length > 0) {
        lines.push(makeMarkdownLinkedHeader(headerLevel, 'Assets', ctx));
        lines.push(makeMarkdownLinkedHeader(headerLevel + 1, 'Summary Table', ctx));
        lines.push(renderAssetTable(tmo.assets));
        lines.push(makeMarkdownLinkedHeader(headerLevel + 1, 'Details', ctx));
        for (const asset of tmo.assets) {
            lines.push(renderAssetDetail(asset, headerLevel, ctx, tmo));
        }
    }
    return lines.join('\n');
}

/**
 * Render threats details section — heading + note + individual threat blocks
 * Python reference: render_tm_report_part() threats block
 * Note: Python calls render_threat(threat, header_level, ctx) where header_level
 * is the base level (e.g., 0 after decrement), while this function receives
 * headerLevel = base + 1 from the caller. So we pass headerLevel - 1 to renderThreat.
 */
export function renderThreats(tmo: ThreatModel, headerLevel: number = 1, ctx: any = {}): string {
    const lines: string[] = [];
    
    lines.push(makeMarkdownLinkedHeader(headerLevel, `${tmo.title} Threats`, ctx));
    lines.push('\n> **Note** This section contains the threat and mitigations identified during the analysis phase.');
    
    for (let i = 0; i < tmo.threats.length; i++) {
        if (i > 1) {
            lines.push('<hr/>');
        }
        lines.push(renderThreat(tmo.threats[i], headerLevel - 1, ctx));
        if (i !== tmo.threats.length - 1) {
            lines.push(PAGEBREAK);
        }
    }
    
    return lines.join('\n');
}

/**
 * Render operational hardening section
 * Python reference: annex operational guide
 */
export function renderOperationalHardening(tmo: ThreatModel, headerLevel: number = 1, ctx: any = {}): string {
    const guideData = tmo.getOperationalGuideData();
    const cms: Countermeasure[] = [];
    Object.keys(guideData).sort().forEach(op => {
        cms.push(...guideData[op].sort((a: any, b: any) => a.id.localeCompare(b.id)));
    });

    const lines: string[] = [];
    const title = 'Operational Security Hardening Guide';
    lines.push(makeMarkdownLinkedHeader(headerLevel, title, ctx));
    
    lines.push('<table markdown="block" style="print-color-adjust: exact; -webkit-print-color-adjust: exact;">');
    lines.push('  <thead><tr><th>Seq</th><th>Countermeasure Details</th></tr></thead>');
    lines.push('  <tbody markdown="block">');
    
    cms.forEach((cm, i) => {
        const parent = cm.parent;
        const parentAnchor = (parent as any)?.anchor || '';
        const parentTitle = (parent as any)?.title || '';
        const parentId = (parent as any)?._id || (parent as any)?.id || '';
        const cond = (parent as any)?.conditional || '';
        
        let opLine = '';
        if (cm.operator && cm.operator !== 'UNDEFINED') {
            opLine = `**Operated by:** ${cm.operator}`;
        }
        
        const condLine = cond ? `**Valid when:** ${cond}` : '';
        
        lines.push(
            `<tr markdown="block"><td>${i + 1}</td><td markdown="block">**Title (ID):** ${cm.title} (\`${cm.id}\`)<br/>\n` +
            `**Mitigates:** <a href="#${parentAnchor}">${parentTitle}</a> (\`${parentId}\`)<br/>\n` +
            `**Description:**\n${condLine}\n<br/>${cm.description}\n<br/>${opLine}</td></tr>`
        );
    });
    
    lines.push('</tbody></table>');
    return lines.join('\n');
}

/**
 * Render keys summary section
 */
export function renderKeysSummary(tmo: ThreatModel, headerLevel: number = 1, ctx: any = {}): string {
    const lines: string[] = [];
    const title = 'Keys classification';
    lines.push(makeMarkdownLinkedHeader(headerLevel, title, ctx));
    
    const appKeys = tmo.getAssetsByProps({ applicationRelated: true, type: 'key' });
    if (appKeys.length > 0) {
        lines.push(makeMarkdownLinkedHeader(headerLevel + 1, 'Application-specific keys', ctx));
        lines.push('Keys issued to processes to communicate in a secure manner, not linked to a specific business logic');
        lines.push(renderKeyTable(appKeys));
    }
    
    const infraKeys = tmo.getAssetsByProps({ infrastructureRelated: true, type: 'key' });
    const certs = tmo.getAssetsByProps({ type: 'certificate' });
    if (infraKeys.length > 0 || certs.length > 0) {
        lines.push(makeMarkdownLinkedHeader(headerLevel + 1, 'Infrastructure Keys and PKI assets', ctx));
        if (infraKeys.length > 0) lines.push(renderKeyTable(infraKeys));
        if (certs.length > 0) lines.push(renderKeyTable(certs));
    }
    
    const creds = [
        ...tmo.getAssetsByProps({ type: 'credential' }),
        ...tmo.getAssetsByProps({ type: 'credentials' }),
        ...tmo.getAssetsByProps({ type: 'secret' })
    ];
    if (creds.length > 0) {
        lines.push(makeMarkdownLinkedHeader(headerLevel + 1, 'Credentials', ctx));
        lines.push(renderKeyTable(creds));
    }
    
    return lines.join('\n');
}

function renderKeyTable(assets: any[]): string {
    const lines: string[] = [];
    lines.push('<table markdown="block" style="print-color-adjust: exact; -webkit-print-color-adjust: exact;">');
    lines.push('  <tr><th>Title (ID)</th><th>Description</th><th>Properties</th></tr>');
    
    for (const a of assets) {
        const typeVal = a.properties?.type || a.type || '';
        lines.push(
            `  <tr><td><strong><a href="#${a.id}">${a.title}</a></strong></td>` +
            `<td><b>${typeVal}</b><br/>${a.description}</td><td>${a.propertiesHTML()}</td></tr>`
        );
    }
    
    lines.push('</table>');
    return lines.join('\n');
}

export function renderAnnexes(tmo: ThreatModel, headerLevel: number = 1, ctx: any = {}): string {
    const lines: string[] = [];
    // Python render_full_report pattern:
    // PAGEBREAK → "Annex 1 Operational Hardening" heading → operational hardening content
    // PAGEBREAK → "Annex 2: Key Summary" heading → keys summary content
    lines.push(PAGEBREAK);
    lines.push(makeMarkdownLinkedHeader(headerLevel + 1, "Annex 1 Operational Hardening", ctx));
    lines.push(renderOperationalHardening(tmo, headerLevel + 1, ctx));
    lines.push(PAGEBREAK);
    lines.push(makeMarkdownLinkedHeader(headerLevel + 1, "Annex 2: Key Summary", ctx));
    lines.push(renderKeysSummary(tmo, headerLevel + 1, ctx));
    // ISO27001 Summary (if applicable)
    if ((tmo as any).ISO27001Ref) {
        lines.push(PAGEBREAK);
        lines.push(renderISO27001Summary(tmo, headerLevel + 1, ctx));
    }
    return lines.join('\n');
}

/**
 * Render ISO27001 Summary section
 * Python reference: ISO27001Report1.render_summary()
 */
function renderISO27001Summary(tmo: ThreatModel, headerLevel: number = 1, ctx: any = {}): string {
    const lines: string[] = [];
    lines.push(makeMarkdownLinkedHeader(headerLevel, 'ISO27001 Summary', ctx));
    lines.push('');
    
    // Build control → threats mapping
    const controlMap = new Map<string, { description: string; threats: any[] }>();
    const allThreats = tmo.getAllDown(Threat);
    
    for (const threat of allThreats) {
        const compliance = (threat as any).compliance;
        if (!compliance) continue;
        
        const isoRefs = extractISO27001Refs(compliance);
        for (const ref of isoRefs) {
            if (!controlMap.has(ref)) {
                controlMap.set(ref, { description: ref, threats: [] });
            }
            controlMap.get(ref)!.threats.push(threat);
        }
    }
    
    lines.push('<table>');
    lines.push('  <thead>');
    lines.push('    <tr>');
    lines.push('      <th>Control ID</th>');
    lines.push('      <th>Description</th>');
    lines.push('      <th>Threats</th>');
    lines.push('    </tr>');
    lines.push('  </thead>');
    lines.push('  <tbody>');
    
    for (const [controlId, data] of [...controlMap.entries()].sort()) {
        const threatLinks = data.threats.map(t => 
            `<a href="#${t.anchor}">${t._id || t.id}</a>`
        ).join(', ');
        lines.push(`    <tr><td>${controlId}</td><td>${data.description}</td><td>${threatLinks}</td></tr>`);
    }
    
    lines.push('  </tbody>');
    lines.push('</table>');
    
    return lines.join('\n');
}

function extractISO27001Refs(compliance: any): string[] {
    const refs: string[] = [];
    if (Array.isArray(compliance)) {
        for (const item of compliance) {
            if (typeof item === 'object' && item !== null) {
                if (item.ISO27001) {
                    if (Array.isArray(item.ISO27001)) {
                        for (const sub of item.ISO27001) {
                            if (typeof sub === 'object' && sub.ref) {
                                refs.push(sub.ref);
                            }
                        }
                    }
                }
            }
        }
    }
    return refs;
}
