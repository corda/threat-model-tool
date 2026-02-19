import ThreatModel from '../models/ThreatModel.js';
import Threat from '../models/Threat.js';

export class MarkdownRenderer {
    private threatModel: ThreatModel;

    constructor(threatModel: ThreatModel) {
        this.threatModel = threatModel;
    }

    /**
     * Renders a full threat model report in Markdown format
     */
    renderFullReport(): string {
        let md = '';
        
        // Title and metadata
        md += `# ${this.threatModel.originDict.title || 'Threat Model'}\n\n`;
        md += `**ID:** ${this.threatModel.id}\n\n`;
        md += `**Version:** ${this.threatModel.originDict.version || '1.0'}\n\n`;
        
        if (this.threatModel.originDict.authors) {
            md += `**Authors:** ${this.threatModel.originDict.authors}\n\n`;
        }

        md += `**Schema Version:** ${this.threatModel.schemaVersion}\n\n`;
        md += `---\n\n`;

        // Scope section
        if (this.threatModel.scope) {
            md += this.renderScope();
        }

        // Analysis section
        if (this.threatModel.originDict.analysis) {
            md += `## Analysis\n\n`;
            md += `${this.threatModel.originDict.analysis}\n\n`;
            md += `---\n\n`;
        }

        // Threats section
        if (this.threatModel.threats && this.threatModel.threats.length > 0) {
            md += this.renderThreats();
        }

        return md;
    }

    private renderScope(): string {
        let md = `## Scope\n\n`;
        
        if (this.threatModel.scope?.description) {
            md += `${this.threatModel.scope.description}\n\n`;
        }

        if (this.threatModel.securityObjectives.length > 0) {
            md += `### Security Objectives\n\n`;
            for (const secObj of this.threatModel.securityObjectives) {
                md += `#### ${secObj.id}: ${secObj.title}\n\n`;
                if (secObj.description) {
                    md += `${secObj.description}\n\n`;
                }
                if (secObj.group) {
                    md += `**Group:** ${secObj.group}\n\n`;
                }
            }
        }

        if (this.threatModel.assets.length > 0) {
            md += `### Assets\n\n`;
            for (const asset of this.threatModel.assets) {
                md += `#### ${asset.id}: ${asset.title}\n\n`;
                if (asset.description) {
                    md += `${asset.description}\n\n`;
                }
                if (asset.type) {
                    md += `**Type:** ${asset.type}\n\n`;
                }
            }
        }

        if (this.threatModel.assumptions.length > 0) {
            md += `### Assumptions\n\n`;
            for (const assumption of this.threatModel.assumptions) {
                md += `- **${assumption.id}:** ${assumption.description}\n`;
            }
            md += `\n`;
        }

        md += `---\n\n`;
        return md;
    }

    private renderThreats(): string {
        let md = `## Threats\n\n`;

        for (const threat of this.threatModel.threats) {
            md += this.renderThreat(threat);
        }

        return md;
    }

    private renderThreat(threat: Threat): string {
        let md = `### ${threat.id}: ${threat.title}\n\n`;

        md += `**Type:** ${threat.threatType}\n\n`;
        
        if (threat.cvssObject) {
            const scoreDesc = threat.getSmartScoreDesc();
            const scoreVal = threat.getSmartScoreVal();
            md += `**CVSS Score:** ${scoreVal.toFixed(1)} (${scoreDesc})\n\n`;
        }

        if (threat.attack) {
            md += `**Attack:**\n\n${threat.attack}\n\n`;
        }

        if (threat.impactDesc) {
            md += `**Impact:**\n\n${threat.impactDesc}\n\n`;
        }

        if (threat.impactedSecObjs.length > 0) {
            md += `**Impacted Security Objectives:**\n`;
            for (const ref of threat.impactedSecObjs) {
                md += `- ${ref.REFIDValue}\n`;
            }
            md += `\n`;
        }

        if (threat.attackers.length > 0) {
            md += `**Attackers:**\n`;
            for (const ref of threat.attackers) {
                md += `- ${ref.REFIDValue}\n`;
            }
            md += `\n`;
        }

        if (threat.countermeasures.length > 0) {
            md += `**Countermeasures:**\n\n`;
            for (const cm of threat.countermeasures) {
                if ('REFIDValue' in cm) {
                    md += `- Reference: ${cm.REFIDValue}\n`;
                } else {
                    const countermeasure = cm as any;
                    md += `- **${countermeasure.id}:** ${countermeasure.title}`;
                    if (countermeasure.inPlace !== undefined) {
                        md += ` (${countermeasure.inPlace ? 'In Place' : 'Not In Place'})`;
                    }
                    md += `\n`;
                    if (countermeasure.description) {
                        md += `  ${countermeasure.description}\n`;
                    }
                }
            }
            md += `\n`;
        }

        if (threat.fullyMitigated !== undefined) {
            md += `**Fully Mitigated:** ${threat.fullyMitigated ? 'Yes' : 'No'}\n\n`;
        }

        md += `---\n\n`;
        return md;
    }

    renderSummary(): string {
        let md = `## Summary\n\n`;
        
        md += `- **Total Threats:** ${this.threatModel.threats.length}\n`;
        
        const mitigatedThreats = this.threatModel.threats.filter(t => t.fullyMitigated === true).length;
        md += `- **Fully Mitigated Threats:** ${mitigatedThreats}\n`;
        md += `- **Unmitigated Threats:** ${this.threatModel.threats.length - mitigatedThreats}\n\n`;

        const severityCounts: Record<string, number> = {};
        for (const threat of this.threatModel.threats) {
            const severity = threat.getSmartScoreDesc();
            severityCounts[severity] = (severityCounts[severity] || 0) + 1;
        }

        md += `**Threat Severity Breakdown:**\n`;
        for (const [severity, count] of Object.entries(severityCounts)) {
            md += `- ${severity}: ${count}\n`;
        }
        md += `\n`;

        return md;
    }
}
