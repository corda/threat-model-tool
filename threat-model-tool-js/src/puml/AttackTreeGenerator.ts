import ThreatModel from '../models/ThreatModel.js';
import Threat from '../models/Threat.js';

export class AttackTreeGenerator {
    /**
     * Generate attack tree in DOT format
     * Output format matches Python exactly
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

        // Render child threat models
        for (const child of tmo.children) {
            if (child instanceof ThreatModel) {
                lines.push(this.renderThreatModelNode(child));
                for (const threat of child.threats) {
                    lines.push(this.renderThreatNode(threat, child));
                }
            }
        }

        lines.push('}');
        lines.push('@enduml');
        
        return lines.join('\n');
    }

    private static renderThreatModelNode(tmo: ThreatModel): string {
        const lines: string[] = [];
        const id = (tmo as any)._id || tmo.id;
        
        lines.push(`"${id}" [fillcolor="#bae9ff", style=filled, shape=ellipse, color="#B85450",`);
        lines.push(' label=');
        lines.push(' <<table border="0" cellborder="0" cellspacing="0">');
        lines.push('   <tr><td align="left">');
        
        // Split title into multiple lines if needed
        const titleLines = this.wrapText(tmo.title, 30);
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
        
        const mitigationStatus = threat.fullyMitigated ? "Mitigated" : "Vulnerable";
        const fillColor = threat.fullyMitigated ? "#D5E8D4" : "#F8CECC";
        const borderColor = threat.fullyMitigated ? "#82B366" : "#E06666";
        const cvssColor = (threat as any).getSmartScoreColor ? (threat as any).getSmartScoreColor() : "gray";
        const cvssDesc = (threat as any).getSmartScoreDesc ? (threat as any).getSmartScoreDesc() : "TODO";

        lines.push(`"${id}" [ fillcolor="${fillColor}", style=filled, shape=polygon, color="${borderColor}", penwidth=2,`);
        lines.push(`    URL="../index.html#${id}",  target="_top",`);
        lines.push('    label=');
        lines.push('    <<table border="0" cellborder="0" cellspacing="0" width="530">');
        lines.push(`     <tr><td align="left"><b>${this.escapeHtml(threat.title)} <i>-${mitigationStatus}</i></b>`);
        lines.push(`     </td>  <td BGCOLOR="${cvssColor}">${cvssDesc}</td></tr>`);
        
        // Attack description
        const attackDesc = this.cleanMarkdownText((threat as any).attack || '');
        const wrappedAttack = this.wrapText(attackDesc, 80);
        lines.push(`     <tr><td align="center" COLSPAN="2">${this.escapeHtml(wrappedAttack.join(' '))}</td></tr>`);
        
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
            
            lines.push(`"${cmId}" [`);
            lines.push(`    fillcolor="${colors.fill}", style=filled, shape=polygon, penwidth=2,`);
            lines.push(`    color="${colors.border}",`);
            lines.push('    label=');
            lines.push('    <<table border="0" cellborder="0" cellspacing="0" width="530">');
            lines.push('      <tr><td align="left">');
            lines.push(`        <b>${this.escapeHtml(cmResolved.title)}</b><br/><br/>`);
            
            const desc = this.cleanMarkdownText(cmResolved.description || '');
            const wrappedDesc = this.wrapText(desc, 80);
            lines.push(`        ${this.escapeHtml(wrappedDesc.join(' '))}`);
            
            lines.push('      </td></tr>');
            lines.push('    </table>>');
            lines.push(']');
            lines.push('');
            lines.push(`"${cmId}" -> "${id}" [label = " mitigates", style="solid", color="green", penwidth=2]`);
            
            cmIndex++;
        }

        // Connect threat to threat model
        lines.push(`"${id}" -> "${tmoId}" [label="impacts ", color="#B85450", style="solid", penwidth=2]`);
        
        return lines.join('\n');
    }

    private static escapeHtml(text: string): string {
        return text
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }

    private static cleanMarkdownText(text: string): string {
        // Remove markdown formatting
        return text
            .replace(/\[([^\]]+)\]\([^\)]+\)/g, '$1')
            .replace(/\*\*/g, '')
            .replace(/\*/g, '')
            .replace(/__/g, '')
            .replace(/_/g, '');
    }

    private static wrapText(text: string, width: number): string[] {
        const words = text.split(/\s+/);
        const lines: string[] = [];
        let currentLine = '';

        for (const word of words) {
            if (currentLine.length + word.length + 1 <= width) {
                currentLine += (currentLine ? ' ' : '') + word;
            } else {
                if (currentLine) lines.push(currentLine);
                currentLine = word;
            }
        }
        if (currentLine) lines.push(currentLine);

        return lines;
    }
}
