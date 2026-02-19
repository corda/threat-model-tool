import ThreatModel from '../models/ThreatModel.js';
import Threat from '../models/Threat.js';

export class PlantUMLRenderer {
    private threatModel: ThreatModel;

    constructor(threatModel: ThreatModel) {
        this.threatModel = threatModel;
    }

    /**
     * Renders threat model as PlantUML diagram
     */
    renderThreatDiagram(): string {
        let puml = '@startuml\n';
        puml += 'title Threat Model Diagram\\n' + (this.threatModel.originDict.title || 'Untitled') + '\n\n';

        puml += 'skinparam rectangle {\n';
        puml += '  BackgroundColor<<Critical>> #cc0500\n';
        puml += '  BackgroundColor<<High>> #df3d03\n';
        puml += '  BackgroundColor<<Medium>> #f9a009\n';
        puml += '  BackgroundColor<<Low>> #ffcb0d\n';
        puml += '  BackgroundColor<<None>> #53aa33\n';
        puml += '  BorderColor Black\n';
        puml += '}\n\n';

        // Render threats as rectangles
        for (const threat of this.threatModel.threats) {
            const severity = threat.getSmartScoreDesc();
            const score = threat.getSmartScoreVal().toFixed(1);
            
            puml += `rectangle "${this.escapePlantUML(threat.title || threat.id)}" as ${threat.id} <<${severity}>> {\n`;
            puml += `  **Type:** ${this.escapePlantUML(threat.threatType || '')}\n`;
            puml += `  **CVSS:** ${score} (${severity})\n`;
            if (threat.fullyMitigated) {
                puml += `  **Status:** Mitigated\n`;
            }
            puml += '}\n\n';
        }

        // Link threats to security objectives
        for (const threat of this.threatModel.threats) {
            for (const secObjRef of threat.impactedSecObjs) {
                const secObj = secObjRef.resolve();
                if (secObj) {
                    puml += `${threat.id} --> ${secObjRef.REFIDValue} : impacts\n`;
                }
            }
        }

        puml += '\n@enduml\n';
        return puml;
    }

    /**
     * Renders security objectives as PlantUML diagram
     */
    renderSecurityObjectivesDiagram(): string {
        let puml = '@startuml\n';
        puml += 'title Security Objectives\\n' + (this.threatModel.originDict.title || 'Untitled') + '\n\n';

        puml += 'skinparam rectangle {\n';
        puml += '  BackgroundColor lightblue\n';
        puml += '  BorderColor darkblue\n';
        puml += '}\n\n';

        // Group security objectives by group
        const groupedObjectives: Record<string, any[]> = {};
        for (const secObj of this.threatModel.securityObjectives) {
            const group = secObj.group || 'Other';
            if (!groupedObjectives[group]) {
                groupedObjectives[group] = [];
            }
            groupedObjectives[group].push(secObj);
        }

        // Render each group
        for (const [group, objectives] of Object.entries(groupedObjectives)) {
            puml += `package "${this.escapePlantUML(group)}" {\n`;
            for (const secObj of objectives) {
                puml += `  rectangle "${this.escapePlantUML(secObj.title || secObj.id)}" as ${secObj.id}\n`;
            }
            puml += '}\n\n';
        }

        // Show relationships
        for (const secObj of this.threatModel.securityObjectives) {
            for (const contributesRef of secObj.contributesTo) {
                puml += `${secObj.id} ..> ${contributesRef.REFIDValue} : contributes to\n`;
            }
        }

        puml += '\n@enduml\n';
        return puml;
    }

    /**
     * Renders attack tree diagram for a specific threat
     */
    renderAttackTree(threat: Threat): string {
        let puml = '@startuml\n';
        puml += `title Attack Tree: ${this.escapePlantUML(threat.title || threat.id)}\n\n`;

        puml += 'skinparam rectangle {\n';
        puml += '  BackgroundColor lightyellow\n';
        puml += '  BorderColor black\n';
        puml += '}\n\n';

        // Root node - the threat
        puml += `rectangle "${this.escapePlantUML(threat.title || threat.id)}" as root {\n`;
        puml += `  ${this.escapePlantUML(threat.threatType || '')}\n`;
        puml += '}\n\n';

        // Attack path
        if (threat.attack) {
            puml += `rectangle "Attack Method" as attack {\n`;
            const attackLines = this.wrapText(threat.attack, 50);
            for (const line of attackLines) {
                puml += `  ${this.escapePlantUML(line)}\n`;
            }
            puml += '}\n';
            puml += 'root --> attack\n\n';
        }

        // Countermeasures as defensive nodes
        if (threat.countermeasures.length > 0) {
            puml += 'package "Countermeasures" {\n';
            for (let i = 0; i < threat.countermeasures.length; i++) {
                const cm = threat.countermeasures[i];
                if ('REFIDValue' in cm) {
                    puml += `  rectangle "${this.escapePlantUML(cm.REFIDValue)}" as cm${i}\n`;
                } else {
                    const countermeasure = cm as any;
                    const status = countermeasure.inPlace ? '[In Place]' : '[Not In Place]';
                    puml += `  rectangle "${this.escapePlantUML(countermeasure.title || countermeasure.id)}\\n${status}" as cm${i}\n`;
                }
                puml += `  attack ..|> cm${i} : mitigated by\n`;
            }
            puml += '}\n';
        }

        puml += '\n@enduml\n';
        return puml;
    }

    /**
     * Renders all attack trees for all threats
     */
    renderAllAttackTrees(): string {
        let allPuml = '';
        
        for (const threat of this.threatModel.threats) {
            allPuml += this.renderAttackTree(threat);
            allPuml += '\n\n';
        }

        return allPuml;
    }

    /**
     * Escape special PlantUML characters
     */
    private escapePlantUML(text: string): string {
        return text
            .replace(/\n/g, '\\n')
            .replace(/"/g, '\\"')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;');
    }

    /**
     * Wrap text to specified width
     */
    private wrapText(text: string, width: number): string[] {
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
