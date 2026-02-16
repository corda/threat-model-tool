import ThreatModel from '../models/ThreatModel.js';
import Threat from '../models/Threat.js';
import SecurityObjective from '../models/SecurityObjective.js';

export class AttackTreeGenerator {
    private static readonly customRed = '#B85450';
    private static readonly wrapLimit = 560;

    /**
     * Generate per-TM attack tree (Python generate_plantuml_for_threat_model)
     */
    static generate(tmo: ThreatModel): string {
        const lines: string[] = [];

        lines.push('@startuml');
        lines.push('digraph G {');
        lines.push('  rankdir="RL";');
        lines.push('  node [shape=plaintext, fontname="Arial" fontsize="12", align="left"];');
        lines.push('');

        // Render threat model node
        lines.push(this.renderThreatModelNode(tmo));

        // Render all threats
        for (const threat of tmo.threats) {
            lines.push(this.renderThreatNode(threat, tmo));
        }

        lines.push('}');
        lines.push('@enduml');

        return lines.join('\n');
    }

    /**
     * Generate complete recursive attack tree (Python COMPLETE_<root>_ATTACKTREE.puml)
     */
    static generateComplete(tmo: ThreatModel): string {
        const lines: string[] = [];
        lines.push('@startuml');
        lines.push('digraph G {');
        lines.push('  rankdir="RL";');
        lines.push('  node [shape=plaintext, fontname="Arial" fontsize="12"];');
        lines.push('');

        this.appendRecursiveThreatModel(lines, tmo);

        lines.push('}');
        lines.push('@enduml');
        return lines.join('\n');
    }

    static generatePerThreat(threat: Threat): string {
        const id = (threat as any)._id || threat.id;
        const lines: string[] = [];
        lines.push('@startuml');
        lines.push('digraph G {');
        lines.push('rankdir="BT";');
        lines.push('  node [shape=plaintext, fontname="Arial" fontsize="12"];');

        const statusColors = threat.statusColors ? threat.statusColors() : { fill: '#F8CECC', border: this.customRed };
        lines.push(`"${id}" [ fillcolor="${statusColors.fill}", style=filled, shape=polygon, color="${statusColors.border}"`);
        lines.push('    label= ');
        lines.push('    <<table border="0" cellborder="0" cellspacing="0">');
        lines.push(`     <tr><td align="center"><b>Threat</b><br/> ${this.wrapTextForPuml(threat.title, 80)}</td></tr>`);

        if ((threat as any).impactedSecObjs && (threat as any).impactedSecObjs.length > 0) {
            lines.push('     <tr><td><table border="0" cellborder="0" cellspacing="8"><tr>');
            for (const secObjRef of (threat as any).impactedSecObjs) {
                const secObj = secObjRef.resolve ? secObjRef.resolve() : secObjRef;
                const secObjId = (secObj as any)?._id || (secObj as any)?.id || secObjRef.REFIDValue || 'UNKNOWN';
                lines.push(`     <td align="center" href="#${secObjId}" bgcolor="#EEEEEE"><font color="blue">${this.escapeHtml(secObjId)}</font></td>`);
            }
            lines.push('     </tr></table></td></tr>');
        }

        lines.push('   </table>>');
        lines.push('   ];');

        const attackText = this.wrapTextForPuml((threat as any).attack || '', 80);
        lines.push(`"${id}_attack" [ fillcolor="#f5f5f5", style=filled, shape=polygon, color="#666666", label =`);
        lines.push('    <<table border="0" cellborder="0" cellspacing="0">');
        lines.push(`     <tr><td align="center"><b>Attack</b><br/>${attackText}</td></tr>`);
        lines.push('   </table>>');
        lines.push('    ]');
        lines.push(`"${id}_attack" -> "${id}"  [label = " exploits"]`);

        let cmIndex = 0;
        for (const cm of threat.countermeasures) {
            const cmResolved = (cm as any).resolve ? (cm as any).resolve() : cm;
            if (!cmResolved || !cmResolved.description) continue;
            const colors = cmResolved.statusColors ? cmResolved.statusColors() : { fill: '#FFF2CC', border: '#D6B656' };
            lines.push(`"${id}_countermeasure${cmIndex}" [`);
            lines.push(`    fillcolor="${colors.fill}", style=filled, shape=polygon, color="${colors.border}", label =`);
            lines.push('    <<table border="0" cellborder="0" cellspacing="0">');
            lines.push(`     <tr><td align="left"><b>Countermeasure</b><br/> ${this.wrapTextForPuml(cmResolved.title || '', 80)}</td></tr>`);
            lines.push('   </table>>');
            lines.push('   ]');
            lines.push(`     "${id}_countermeasure${cmIndex}" -> "${id}_attack" [label = " mitigates"]`);
            cmIndex++;
        }

        lines.push('}');
        lines.push('@enduml');
        return lines.join('\n');
    }

    static generateSecObjectiveTree(root: ThreatModel, secObj: SecurityObjective): string {
        const secObjId = (secObj as any)._id || secObj.id;
        const lines: string[] = [];
        lines.push('@startuml');
        lines.push('digraph G {');
        lines.push('rankdir="RL";');
        lines.push('node [shape=plaintext, fontname="Arial" fontsize="12", align="left"];');
        lines.push('');

        lines.push(`"${secObjId}" [fillcolor="#bae9ff", style=filled, shape=ellipse, color="${this.customRed}", penwidth=2, label=`);
        lines.push('<<table border="0" cellborder="0" cellspacing="0">');
        lines.push(`  <tr><td align="center"><b>${this.wrapTextForPuml(secObjId, 27)}</b><br/>${this.wrapTextForPuml((secObj as any).description || '', 80)}</td></tr>`);
        lines.push('</table>>]');

        const allThreats = this.getAllThreats(root);
        for (const threat of allThreats) {
            const impactedRefs = (threat as any).impactedSecObjs || [];
            const impactsThis = impactedRefs.some((ref: any) => {
                const resolved = ref.resolve ? ref.resolve() : null;
                const refId = resolved ? ((resolved as any)._id || (resolved as any).id) : ref.REFIDValue;
                return refId === secObjId || refId === secObj.id;
            });
            if (!impactsThis) continue;

            lines.push(this.renderThreatNodeForSecObj(threat));
            const lineStyle = threat.fullyMitigated ? 'dashed' : 'solid';
            const lineColor = threat.fullyMitigated ? 'green' : this.customRed;
            const lineText = threat.fullyMitigated ? '' : 'impacts';
            lines.push(`"${(threat as any)._id || threat.id}" -> "${secObjId}" [label="${lineText} ", color="${lineColor}", style="${lineStyle}", penwidth=2]`);
        }

        lines.push('}');
        lines.push('@enduml');
        return lines.join('\n');
    }

    static generateSecObjectivesOverview(tmo: ThreatModel): string {
        const lines: string[] = [];
        lines.push('@startuml');
        lines.push('digraph G {');
        lines.push(' rankdir="BT";');
        lines.push(' ranksep=2;');
        lines.push('  node [fontname="Arial" fontsize="14" color=LightGray style=filled shape="box"];');
        lines.push('');

        const securityObjectives = tmo.securityObjectives || [];
        const groupMembers = new Map<string, string[]>();
        const edges: Array<[string, string]> = [];

        for (const so of securityObjectives) {
            const soId = (so as any)._id || so.id;
            const group = ((so as any).group || '').toString();
            if (!groupMembers.has(group)) {
                groupMembers.set(group, []);
            }
            groupMembers.get(group)!.push(soId);

            const contributesTo = (so as any).contributesTo || [];
            for (const parentRef of contributesTo) {
                const resolved = parentRef.resolve ? parentRef.resolve() : parentRef;
                const parentId = (resolved as any)?._id || (resolved as any)?.id || parentRef.REFIDValue;
                if (parentId) {
                    edges.push([soId, parentId]);
                }
            }
        }

        for (const [group, members] of groupMembers.entries()) {
            const rawCluster = group && group.length > 0 ? group.replace(/\s+/g, '_') : 'Ungrouped';
            const clusterId = rawCluster.replace(/[^A-Za-z0-9_]/g, '_');
            const label = this.escapeHtml(group || 'Ungrouped').replace(/&quot;/g, '"');
            const nodeList = members.map((member) => `"${member}";`).join(' ');
            lines.push(`subgraph cluster_${clusterId} {  label = "${label}";  ${nodeList} }`);
        }

        for (const [child, parent] of edges) {
            lines.push(`"${child}" -> "${parent}" [label = "contributes to"]`);
        }

        lines.push('');
        lines.push('## (threat -> secObj edges omitted)');
        lines.push('');
        lines.push('}');
        lines.push('@enduml');
        return lines.join('\n');
    }

    private static appendRecursiveThreatModel(lines: string[], tmo: ThreatModel): void {
        lines.push(this.renderThreatModelNode(tmo));
        for (const threat of tmo.threats) {
            lines.push(this.renderThreatNode(threat, tmo));
            lines.push(`"${(threat as any)._id || threat.id}" -> "${(tmo as any)._id || tmo.id}" [label=" impacts"]`);
        }
        for (const child of tmo.getDescendantsTM().filter((candidate) => candidate.parent === tmo)) {
            lines.push(this.renderThreatModelNode(child));
            lines.push(`"${(child as any)._id || child.id}" -> "${(tmo as any)._id || tmo.id}" [label=" in scope for "]`);
            this.appendRecursiveThreatModel(lines, child);
        }
    }

    private static renderThreatModelNode(tmo: ThreatModel): string {
        const lines: string[] = [];
        const id = (tmo as any)._id || tmo.id;
        
        lines.push(`"${id}" [fillcolor="#bae9ff", style=filled, shape=ellipse, color="${this.customRed}",`);
        lines.push(' label=');
        lines.push(' <<table border="0" cellborder="0" cellspacing="0">');
        lines.push('   <tr><td align="left">');
        
        // Split title into multiple lines if needed
        const titleLines = this.wrapText(this.escapeHtml(this.cleanMarkdownText(tmo.title || '')), 27);
        for (let i = 0; i < titleLines.length; i++) {
            lines.push(`     <b>${this.escapeHtml(titleLines[i])}</b>`);
            if (i < titleLines.length - 1) {
                lines.push('<br/>');
            }
        }
        
        lines.push('   </td></tr>');
        lines.push(' </table>>]');
        
        return lines.join('\n');
    }

    private static renderThreatNode(threat: Threat, tmo: ThreatModel): string {
        const lines: string[] = [];
        const id = (threat as any)._id || threat.id;
        const tmoId = (tmo as any)._id || tmo.id;
        
        const mitigationStatus = threat.statusDefaultText ? threat.statusDefaultText() : (threat.fullyMitigated ? 'Mitigated' : 'Vulnerable');
        const statusColors = threat.statusColors ? threat.statusColors() : { fill: '#F8CECC', border: '#E06666' };
        const fillColor = statusColors.fill;
        const borderColor = statusColors.border;
        const cvssColor = (threat as any).getSmartScoreColor ? (threat as any).getSmartScoreColor() : "gray";
        const cvssDesc = (threat as any).getSmartScoreDesc ? (threat as any).getSmartScoreDesc() : "TODO";

        lines.push(`"${id}" [ fillcolor="${fillColor}", style=filled, shape=polygon, color="${borderColor}", penwidth=2,`);
        lines.push(`    URL="../index.html#${id}",  target="_top", `);
        lines.push('    label= ');
        lines.push('    <<table border="0" cellborder="0" cellspacing="0" width="530">');
        lines.push(`     <tr><td align="left"><b>${this.wrapTextForPuml(threat.title, 80)} <i>-${mitigationStatus}</i></b> `);
        lines.push(`     </td>  <td BGCOLOR="${cvssColor}">${cvssDesc}</td></tr>`);
        
        // Attack description
        lines.push(`     <tr><td align="center" COLSPAN="2">${this.wrapTextForPuml((threat as any).attack || '', 80)}</td></tr>   `);
        
        lines.push('   </table>>');
        lines.push('];');
        lines.push('');

        // Render countermeasures
        let cmIndex = 0;
        for (const cm of threat.countermeasures) {
            const cmResolved = (cm as any).resolve ? (cm as any).resolve() : cm;
            if (!cmResolved) continue;

            const colors = cmResolved.statusColors ? cmResolved.statusColors() : { fill: "#FFF2CC", border: "#D6B656" };
            const cmId = `${id}_countermeasure${cmIndex}`;
            const lineStyle = cmResolved.inPlace ? 'solid' : 'dashed';
            const lineColor = cmResolved.inPlace ? 'green' : this.customRed;
            const lineText = cmResolved.inPlace ? 'mitigates' : '';
            
            lines.push(`"${cmId}" [`);
            lines.push(`    fillcolor="${colors.fill}", style=filled, shape=polygon, penwidth=2,`);
            lines.push(`    color="${colors.border}", `);
            lines.push('    label=');
            lines.push('    <<table border="0" cellborder="0" cellspacing="0" width="530">');
            lines.push('      <tr><td align="left">');
            lines.push(`        <b>${this.wrapTextForPuml(cmResolved.title || '', 80)}</b><br/><br/> `);
            
            lines.push(`        ${this.wrapTextForPuml(cmResolved.description || '', 80)}`);
            
            lines.push('      </td></tr>');
            lines.push('    </table>>');
            lines.push(']');
            lines.push('');
            lines.push(`"${cmId}" -> "${id}" [label = " ${lineText}", style="${lineStyle}", color="${lineColor}", penwidth=2]`);
            lines.push('                ');
            lines.push('                ');
            
            cmIndex++;
        }

        // Connect threat to threat model
        const threatLineStyle = threat.fullyMitigated ? 'dashed' : 'solid';
        const threatLineColor = threat.fullyMitigated ? 'green' : this.customRed;
        const threatLineText = threat.fullyMitigated ? '' : 'impacts';
        lines.push(`"${id}" -> "${tmoId}" [label="${threatLineText} ", color="${threatLineColor}", style="${threatLineStyle}", penwidth=2]`);
        
        return lines.join('\n');
    }

    private static renderThreatNodeForSecObj(threat: Threat): string {
        const id = (threat as any)._id || threat.id;
        const mitigationStatus = threat.statusDefaultText ? threat.statusDefaultText() : (threat.fullyMitigated ? 'Mitigated' : 'Vulnerable');
        const statusColors = threat.statusColors ? threat.statusColors() : { fill: '#F8CECC', border: '#E06666' };
        const cvssColor = (threat as any).getSmartScoreColor ? (threat as any).getSmartScoreColor() : 'gray';
        const cvssDesc = (threat as any).getSmartScoreDesc ? (threat as any).getSmartScoreDesc() : 'TODO';

        const lines: string[] = [];
        lines.push(`"${id}" [ fillcolor="${statusColors.fill}", style=filled, shape=polygon, color="${statusColors.border}", penwidth=2,`);
        lines.push(`    URL="../index.html#${id}",  target="_top", `);
        lines.push('    label= ');
        lines.push('    <<table border="0" cellborder="0" cellspacing="0" width="530">');
        lines.push(`     <tr><td align="left"><b>${this.wrapTextForPuml(threat.title, 80)} <i>-${mitigationStatus}</i></b> `);
        lines.push(`     </td>  <td BGCOLOR="${cvssColor}">${cvssDesc}</td></tr>`);
        lines.push(`     <tr><td align="center" COLSPAN="2">${this.wrapTextForPuml((threat as any).attack || '', 80)}</td></tr>   `);
        lines.push('   </table>>');
        lines.push('];');
        lines.push('');

        let cmIndex = 0;
        for (const cm of threat.countermeasures) {
            const cmResolved = (cm as any).resolve ? (cm as any).resolve() : cm;
            if (!cmResolved) continue;

            const colors = cmResolved.statusColors ? cmResolved.statusColors() : { fill: '#FFF2CC', border: '#D6B656' };
            const lineStyle = cmResolved.inPlace ? 'solid' : 'dashed';
            const lineColor = cmResolved.inPlace ? 'green' : this.customRed;
            const lineText = cmResolved.inPlace ? 'mitigates' : '';
            const cmId = `${id}_countermeasure${cmIndex}`;

            lines.push(`"${cmId}" [`);
            lines.push(`    fillcolor="${colors.fill}", style=filled, shape=polygon, penwidth=2,`);
            lines.push(`    color="${colors.border}", `);
            lines.push('    label=');
            lines.push('    <<table border="0" cellborder="0" cellspacing="0" width="530">');
            lines.push('      <tr><td align="left">');
            lines.push(`        <b>${this.wrapTextForPuml(cmResolved.title || '', 80)}</b><br/><br/> `);
            lines.push(`        ${this.wrapTextForPuml(cmResolved.description || '', 80)}`);
            lines.push('      </td></tr>');
            lines.push('    </table>>');
            lines.push(']');
            lines.push('');
            lines.push(`"${cmId}" -> "${id}" [label = " ${lineText}", style="${lineStyle}", color="${lineColor}", penwidth=2]`);
            lines.push('                ');
            lines.push('                ');

            cmIndex++;
        }

        return lines.join('\n');
    }

    static getAllThreats(root: ThreatModel): Threat[] {
        const models = [root, ...root.getDescendantsTM()];
        const threats: Threat[] = [];
        for (const model of models) {
            threats.push(...model.threats);
        }
        return threats;
    }

    static getAllSecurityObjectives(root: ThreatModel): SecurityObjective[] {
        const models = [root, ...root.getDescendantsTM()];
        const secObjs: SecurityObjective[] = [];
        for (const model of models) {
            secObjs.push(...model.securityObjectives);
        }
        return secObjs;
    }

    private static escapeHtml(text: string): string {
        return text
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#x27;');
    }

    private static cleanMarkdownText(text: string): string {
        // Mirror Python template_utils.clean_markdown_text behavior
        // - [text](link) -> text
        // - strip trailing '**Refs:' or '**Ref:' section
        return text
            .replace(/\[([^\]]+)\]\([^\)]+\)/g, '$1')
            .replace(/\*\*Refs?:.*$/s, '');
    }

    private static wrapText(text: string, width: number): string[] {
        const normalized = (text || '').replace(/[\t\r\n\f\v]+/g, ' ');
        const tokens = normalized.match(/\S+|\s+/g) || [];
        const lines: string[] = [];
        let currentLine = '';

        for (const token of tokens) {
            if (/^\s+$/.test(token)) {
                if (!currentLine) {
                    continue;
                }
                const next = currentLine + token;
                if (next.length <= width) {
                    currentLine = next;
                }
            } else {
                if (currentLine.length + token.length <= width) {
                    currentLine += token;
                } else {
                    if (currentLine.trim().length > 0) {
                        lines.push(currentLine.replace(/\s+$/g, ''));
                    }
                    currentLine = token;
                }
            }
        }
        if (currentLine.trim().length > 0) {
            lines.push(currentLine.replace(/\s+$/g, ''));
        }

        return lines;
    }

    private static wrapTextForPuml(text: string, width = 80, limit = this.wrapLimit): string {
        const cleaned = this.cleanMarkdownText(text || '').trim();
        if (!cleaned) {
            return '';
        }
        const truncated = cleaned.length > limit ? `${cleaned.slice(0, limit)}[...]` : cleaned;
        const escaped = this.escapeHtml(truncated);
        return this.wrapText(escaped, width).join('<br/>');
    }
}
