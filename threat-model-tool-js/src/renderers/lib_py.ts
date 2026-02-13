import ThreatModel from '../models/ThreatModel.js';
import Threat from '../models/Threat.js';
import Countermeasure from '../models/Countermeasure.js';
import { makeMarkdownLinkedHeader, PAGEBREAK, createObjectAnchorHash } from '../utils/TemplateUtils.js';
import * as html from 'html-escaper';

/**
 * Render executive summary section
 * Python reference: lib_py.py lines 53-99
 */
export function executiveSummary(tmo: ThreatModel, headerLevel: number = 1, ctx: any = {}): string {
    const unmitNoOp = tmo.getThreatsByFullyMitigatedAndOperational(false, false);
    
    const lines: string[] = [];
    
    lines.push(makeMarkdownLinkedHeader(headerLevel + 1, "Executive Summary", ctx, false));
    lines.push("> This section contains an executive summary of the threats and their mitigation status.\n");

    if (unmitNoOp.length < 1) {
        lines.push("**No unmitigated threats without operational countermeasures were identified**");
    } else {
        lines.push(`There are **${unmitNoOp.length}** unmitigated threats without proposed operational controls.<br/>`);
        lines.push('<div markdown="1">');
        lines.push('<table markdown="block" style="print-color-adjust: exact; -webkit-print-color-adjust: exact;">');
        lines.push("<tr><th>Threat ID</th><th>Severity</th></tr>");
        
        for (const threat of unmitNoOp) {
            const anchor = createObjectAnchorHash(threat);
            const cvssColor = threat.getSmartScoreColor();
            const cvssDesc = threat.getSmartScoreDesc();
            const parentId = (threat.parent as any)?._id || '';
            
            const cvssTd = `<td style="background-color: ${cvssColor}; " > <span markdown="block" style="font-weight:bold; color:white;"><strong>${cvssDesc}</strong></span> </td>`;
            
            let row = '<tr markdown="block"><td>';
            row += `<a href="#${anchor}">${parentId}.<br/>${threat.id}</a>`;
            
            if (threat.ticketLink) {
                row += `<br/><a href="${html.escape(threat.ticketLink)}"> Ticket link  </a>`;
            }
            
            row += `</td>${cvssTd}</tr>`;
            lines.push(row);
        }
        
        lines.push("</table>");
        lines.push("</div>");
    }

    return lines.join('\n');
}

/**
 * Render threats summary table
 * Python reference: lib_py.py - threats_summary function
 */
export function threatsSummary(tmo: ThreatModel, headerLevel: number = 1, ctx: any = {}): string {
    const allThreats = [...tmo.threats];
    const descendantTMs = tmo.getDescendantsTM();
    
    for (const childTM of descendantTMs) {
        allThreats.push(...childTM.threats);
    }

    const unmitigated = allThreats.filter(t => !t.fullyMitigated);
    const unmitNoOp = allThreats.filter(t => !t.fullyMitigated && !t.operational);

    const lines: string[] = [];
    lines.push(makeMarkdownLinkedHeader(headerLevel + 2, "Threats Summary", ctx, false));
    lines.push(`There are a total of **${allThreats.length}** identified threats of which **${unmitigated.length}** are not fully mitigated by default, and  **${unmitNoOp.length}** are unmitigated without proposed operational controls.<br/>`);
    
    lines.push('<div markdown="1">');
    lines.push('<table markdown="block" style="print-color-adjust: exact; -webkit-print-color-adjust: exact;">');
    lines.push("<tr><th>Threat ID</th><th>CVSS</th><th>Mitigation Status</th></tr>");

    for (const threat of allThreats) {
        const anchor = createObjectAnchorHash(threat);
        const parentId = (threat.parent as any)?._id || '';
        const cvssColor = threat.getSmartScoreColor();
        const cvssDesc = threat.getSmartScoreDesc();
        
        let mitigationStatus = "Vulnerable";
        let statusColor = "#F8CECC";
        
        if (threat.fullyMitigated) {
            mitigationStatus = "Mitigated";
            statusColor = "#D5E8D4";
        }

        let row = '<tr markdown="block">';
        row += `<td><a href="#${anchor}">${parentId}.<br/>${threat.id}</a></td>`;
        row += `<td style="background-color: ${cvssColor}; " ><span markdown="block" style="font-weight:bold; color:white;"><strong>${cvssDesc}</strong></span></td>`;
        row += `<td style="background-color: ${statusColor};text-align: center ">${mitigationStatus}</td>`;
        row += '</tr>';
        
        lines.push(row);
    }

    lines.push("</table></div>");
    return lines.join('\n');
}

/**
 * Render security objectives section
 */
export function renderSecurityObjectives(tmo: ThreatModel, headerLevel: number = 2, ctx: any = {}): string {
    const lines: string[] = [];
    
    lines.push(makeMarkdownLinkedHeader(headerLevel, `${tmo.title} security objectives`, ctx));
    
    // Group by group attribute
    const groups: Record<string, any[]> = {};
    for (const secObj of tmo.securityObjectives) {
        const group = secObj.group || 'Other';
        if (!groups[group]) {
            groups[group] = [];
        }
        groups[group].push(secObj);
    }

    // Render grouped list
    for (const [groupName, objectives] of Object.entries(groups)) {
        lines.push(`**${groupName}:**\n`);
        for (const obj of objectives) {
            lines.push(`- <a href="#${obj.anchor}">${obj.title}</a>\n`);
        }
        lines.push("");
    }

    // Add diagram reference
    lines.push("**Diagram:**");
    lines.push('<img src="img/secObjectives.svg"/>');
    lines.push("**Details:**\n");

    // Render each objective
    for (const secObj of tmo.securityObjectives) {
        lines.push(makeMarkdownLinkedHeader(headerLevel + 1, `${secObj.title} (<code>${secObj.id}</code>)`, ctx, false, secObj));
        lines.push(`\n${secObj.description}`);
        
        if (secObj.priority) {
            lines.push(`**Priority:** ${secObj.priority}\n`);
        }

        // Contributes to
        if (secObj.contributesTo && secObj.contributesTo.length > 0) {
            lines.push("**Contributes to:**\n");
            for (const ref of secObj.contributesTo) {
                const resolved = ref.resolve() as any;
                if (resolved) {
                    lines.push(`- <code><a href="#${resolved.anchor}">${resolved.id}</a></code> *(${resolved.title})*\n`);
                }
            }
        }

        // Attack tree diagram
        if (secObj.treeImage) {
            lines.push("**Attack tree:**\n");
            lines.push(`<img src="img/secObjectives/${secObj.id}.svg"/>`);
            lines.push('<img src="img/legend_SecObjTree.svg" width="400"/>');
        }
        
        lines.push("<hr/>\n");
    }

    return lines.join('\n');
}

/**
 * Render linked threat models section
 */
export function renderLinkedThreatModels(tmo: ThreatModel, headerLevel: number = 2, ctx: any = {}): string {
    const lines: string[] = [];
    const internalChildren = Array.from(tmo.children).filter(c => c instanceof ThreatModel).map(c => c as any as ThreatModel);
    
    if (internalChildren.length > 0) {
        lines.push(makeMarkdownLinkedHeader(headerLevel, "Linked threat Models", ctx));
        for (const child of internalChildren) {
            lines.push(`- **${child.title}** (ID: ${child.id})`);
        }
        lines.push('<div class="pagebreak"></div>\n');
    }
    
    return lines.join('\n');
}

/**
 * Render attackers section
 */
export function renderAttackers(tmo: ThreatModel, headerLevel: number = 2, ctx: any = {}): string {
    const lines: string[] = [];
    
    lines.push(makeMarkdownLinkedHeader(headerLevel, `${tmo.title} Threat Actors`, ctx));
    lines.push("> Actors, agents, users and attackers may be used as synonymous.\n");
    
    for (const attacker of tmo.attackers) {
        lines.push(`<a id="${attacker.id}"></a>`);
        lines.push(`**${attacker.title} (<code>${attacker.id}</code>)**`);
        if (attacker.description) {
            lines.push(attacker.description);
        }
        lines.push("");
    }
    
    return lines.join('\n');
}

/**
 * Render assumptions section
 */
export function renderAssumptions(tmo: ThreatModel, headerLevel: number = 2, ctx: any = {}): string {
    const lines: string[] = [];
    if (tmo.assumptions.length > 0) {
        lines.push(makeMarkdownLinkedHeader(headerLevel, "Assumptions", ctx));
        for (const assumption of tmo.assumptions) {
            lines.push(`- **${assumption.title}**: ${assumption.description}`);
        }
        lines.push("");
    }
    return lines.join('\n');
}

/**
 * Render assets section
 */
export function renderAssets(tmo: ThreatModel, headerLevel: number = 2, ctx: any = {}): string {
    const lines: string[] = [];
    if (tmo.assets.length > 0) {
        lines.push(makeMarkdownLinkedHeader(headerLevel, "Assets", ctx));
        
        lines.push(makeMarkdownLinkedHeader(headerLevel + 1, "Summary Table", ctx, false));
        lines.push('<div markdown="1">');
        lines.push('<table markdown="block">');
        lines.push("<tr><th>Asset</th><th>Type</th><th>Description</th></tr>");
        
        for (const asset of tmo.assets) {
            lines.push(`<tr markdown="block"><td>${asset.title}</td><td>${asset.type || ''}</td><td>${asset.description}</td></tr>`);
        }
        lines.push("</table></div>\n");

        lines.push(makeMarkdownLinkedHeader(headerLevel + 1, "Details", ctx, false));
        for (const asset of tmo.assets) {
            lines.push(`**${asset.title} (<code>${asset.id}</code>)**`);
            lines.push(asset.description);
            if (Object.keys(asset.properties).length > 0) {
                lines.push(asset.propertiesHTML());
            }
            lines.push("");
        }
    }
    return lines.join('\n');
}

/**
 * Render threats details section
 */
export function renderThreats(tmo: ThreatModel, headerLevel: number = 1, ctx: any = {}): string {
    const lines: string[] = [];
    
    lines.push(makeMarkdownLinkedHeader(headerLevel, `${tmo.title} Threats`, ctx));
    
    for (const threat of tmo.threats) {
        const anchor = createObjectAnchorHash(threat);
        lines.push(makeMarkdownLinkedHeader(headerLevel + 1, `${threat.title} (<code>${threat.id}</code>)`, ctx, false, threat));
        
        lines.push(threat.description);
        lines.push("");
        
        const cvssDesc = threat.getSmartScoreDesc();
        const cvssColor = threat.getSmartScoreColor();
        lines.push(`**Severity:** <span style="background-color: ${cvssColor}; color: white; padding: 2px 5px; border-radius: 3px;">**${cvssDesc}**</span>\n`);

        if (threat.countermeasures.length > 0) {
            lines.push("**Countermeasures:**\n");
            for (const cm of threat.countermeasures) {
                const resolved = (cm as any).resolve ? (cm as any).resolve() : cm;
                if (resolved) {
                    const status = resolved.inPlace ? "In Place" : "Planned";
                    const color = resolved.inPlace ? "green" : "orange";
                    lines.push(`- **${resolved.title}** [<span style="color: ${color}">${status}</span>]`);
                    lines.push(`  ${resolved.description}\n`);
                }
            }
        }
        
        
        lines.push("<hr/>\n");
    }
    
    return lines.join('\n');
}

/**
 * Render operational hardening section
 */
export function renderOperationalHardening(tmo: ThreatModel, headerLevel: number = 1, ctx: any = {}): string {
    const guideData = tmo.getOperationalGuideData();
    const cms: Countermeasure[] = [];
    Object.keys(guideData).sort().forEach(op => {
        cms.push(...guideData[op].sort((a, b) => a.id.localeCompare(b.id)));
    });

    const lines: string[] = [];
    const title = ctx.annexTitle || "Operational Security Hardening Guide";
    lines.push(makeMarkdownLinkedHeader(headerLevel, title, ctx));
    
    lines.push('<table markdown="block" style="print-color-adjust: exact; -webkit-print-color-adjust: exact;">');
    lines.push("  <thead><tr><th>Seq</th><th>Countermeasure Details</th></tr></thead>");
    lines.push("  <tbody markdown=\"block\">");
    
    cms.forEach((cm, i) => {
        const parent = cm.parent;
        const parentAnchor = (parent as any)?.anchor || '';
        const parentTitle = (parent as any)?.title || '';
        const parentId = (parent as any)?._id || (parent as any)?.id || '';
        const cond = (parent as any)?.conditional || '';
        
        let opLine = "";
        if (cm.operator && cm.operator !== "UNDEFINED") {
            opLine = `**Operated by:** ${cm.operator}`;
        }
        
        const condLine = cond ? `**Valid when:** ${cond}` : "";
        
        lines.push(
            `<tr markdown="block"><td>${i + 1}</td><td markdown="block">**Title (ID):** ${cm.title} (\`${cm.id}\`) <br/>\n` +
            `**Mitigates:** <a href="#${parentAnchor}">${parentTitle}</a> (\`${parentId}\`) <br/>\n` +
            `**Description:**\n${condLine}\n<br/>${cm.description}\n<br/>${opLine}</td></tr>`
        );
    });
    
    lines.push("</tbody></table>");
    return lines.join('\n');
}

/**
 * Render keys summary section
 */
export function renderKeysSummary(tmo: ThreatModel, headerLevel: number = 1, ctx: any = {}): string {
    const lines: string[] = [];
    const title = ctx.annexTitle || "Keys classification ";
    lines.push(makeMarkdownLinkedHeader(headerLevel, title, ctx));
    
    const appKeys = tmo.getAssetsByProps({ applicationRelated: true, type: "key" });
    if (appKeys.length > 0) {
        lines.push(makeMarkdownLinkedHeader(headerLevel + 1, "Application-specific keys", ctx));
        lines.push("Keys issued to processes to communicate in a secure manner, not linked to a specific business logic");
        lines.push(renderKeyTable(appKeys));
    }
    
    const infraKeys = tmo.getAssetsByProps({ infrastructureRelated: true, type: "key" });
    const certs = tmo.getAssetsByProps({ type: "certificate" });
    if (infraKeys.length > 0 || certs.length > 0) {
        lines.push(makeMarkdownLinkedHeader(headerLevel + 1, "Infrastructure Keys and PKI assets", ctx));
        if (infraKeys.length > 0) lines.push(renderKeyTable(infraKeys));
        if (certs.length > 0) lines.push(renderKeyTable(certs));
    }
    
    const creds = [
        ...tmo.getAssetsByProps({ type: "credential" }),
        ...tmo.getAssetsByProps({ type: "credentials" }),
        ...tmo.getAssetsByProps({ type: "secret" })
    ];
    if (creds.length > 0) {
        lines.push(makeMarkdownLinkedHeader(headerLevel + 1, "Credentials", ctx));
        lines.push(renderKeyTable(creds));
    }
    
    return lines.join('\n');
}

function renderKeyTable(assets: any[]): string {
    const lines: string[] = [];
    lines.push('<table markdown="block" style="print-color-adjust: exact; -webkit-print-color-adjust: exact;">');
    lines.push("  <tr><th>Title (ID)</th><th>Description</th><th>Properties</th></tr>");
    
    for (const a of assets) {
        const typeVal = a.properties?.type || a.type || "";
        lines.push(
            `  <tr><td><strong><a href="#${a.id}">${a.title}</a></strong></td>` +
            `<td><b>${typeVal}</b><br/>${a.description}</td><td>${a.propertiesHTML()}</td></tr>`
        );
    }
    
    lines.push("</table>");
    return lines.join('\n');
}

export function renderAnnexes(tmo: ThreatModel, headerLevel: number = 1, ctx: any = {}): string {
    const lines: string[] = [];
    lines.push(PAGEBREAK);
    lines.push(renderOperationalHardening(tmo, headerLevel + 1, { ...ctx, annexTitle: "Annex 1: Operational Security Hardening Guide" }));
    lines.push(PAGEBREAK);
    lines.push(renderKeysSummary(tmo, headerLevel + 1, { ...ctx, annexTitle: "Annex 2: Keys classification " }));
    return lines.join('\n');
}
