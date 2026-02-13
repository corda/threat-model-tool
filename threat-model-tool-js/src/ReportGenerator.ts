import fs from 'fs';
import path from 'path';
import ThreatModel from './models/ThreatModel.js';
import { 
    executiveSummary, 
    threatsSummary, 
    renderSecurityObjectives,
    renderLinkedThreatModels,
    renderAttackers,
    renderAssumptions,
    renderAssets,
    renderThreats,
    renderAnnexes
} from './renderers/lib_py.js';
import { AttackTreeGenerator } from './puml/AttackTreeGenerator.js';
import { HeadingNumberer, resetHeadingNumbers, disableHeadingNumbering, enableHeadingNumbering, isHeadingNumberingEnabled } from './utils/HeadingNumberer.js';
import { makeMarkdownLinkedHeader, createTitleAnchorHash, PAGEBREAK } from './utils/TemplateUtils.js';

export class ReportGenerator {
    /**
     * Generate full report for a threat model
     */
    static generate(
        tmo: ThreatModel,
        template: string = 'full',
        outputDir: string,
        ctx: any = {}
    ): void {
        const id = (tmo as any)._id || tmo.id;
        const mdOutFileName = path.join(outputDir, `${id}.md`);

        // Prepare output directory
        fs.mkdirSync(outputDir, { recursive: true });
        fs.mkdirSync(path.join(outputDir, 'img'), { recursive: true });

        // Reset heading numbers
        resetHeadingNumbers();

        // Set context defaults
        const context = {
            processToc: true,
            process_prepost_md: true,
            process_heading_numbering: true,
            mainTitle: ctx.mainTitle || null,
            ...ctx
        };

        // Render report using the Python-aligned pipeline
        let mdReport = this.renderFullReport(tmo, context);

        // Inject TOC
        if (context.processToc) {
            const toc = this.generateTOC(mdReport);
            mdReport = mdReport.replace('__TOC_PLACEHOLDER__', toc);
        }

        // Write markdown file (ensure trailing newline to match Python)
        if (!mdReport.endsWith('\n')) {
            mdReport += '\n';
        }
        fs.writeFileSync(mdOutFileName, mdReport, 'utf8');
        console.log(`Generated: ${mdOutFileName}`);

        // Generate PlantUML diagrams
        this.generatePlantUML(tmo, outputDir);
    }

    /**
     * Render a full report matching Python render_full_report():
     * - render_tm_report_part(root, ancestor_data=True, toc=True, summary=True)
     * - render_tm_report_part(each descendant, ancestor_data=False)
     * - Annex 1: Operational Hardening
     * - Annex 2: Keys Classification
     * - (optional: ISO27001 Summary)
     */
    private static renderFullReport(tmo: ThreatModel, ctx: any): string {
        resetHeadingNumbers();
        const lines: string[] = [];

        // Root part: with TOC and summary
        lines.push(this.renderTmReportPart(tmo, true, true, true, 1, ctx));

        // Descendants
        for (const descendant of tmo.getDescendantsTM()) {
            lines.push(this.renderTmReportPart(descendant, false, false, false, 1, ctx));
        }

        // Annexes
        lines.push(renderAnnexes(tmo, 1, ctx));

        return lines.join('\n');
    }

    /**
     * Port of Python render_tm_report_part().
     * Renders a single ThreatModel as a markdown section.
     */
    private static renderTmReportPart(
        tmo: ThreatModel,
        ancestorData: boolean,
        toc: boolean = false,
        summary: boolean = false,
        headerLevel: number = 1,
        ctx: any = {}
    ): string {
        const lines: string[] = [];
        const id = (tmo as any)._id || tmo.id;

        // Disable numbering for root title section (re-enable after TOC)
        const defaultEnabled = isHeadingNumberingEnabled();
        if (defaultEnabled && tmo.isRoot()) {
            disableHeadingNumbering();
        }

        // Opening div
        const cssClass = (tmo as any).proposal ? 'proposal' : 'current';
        lines.push(`<div markdown="block" class='${cssClass}'>`);

        if ((tmo as any).proposal) {
            lines.push(`From proposal: ${(tmo as any).proposal}\n`);
        }

        // Title
        let title = tmo.title + ' Threat Model';
        if (!tmo.isRoot()) {
            title = title + ' Section';
        }
        if (ctx.mainTitle && tmo.isRoot()) {
            title = ctx.mainTitle;
        }

        // Title heading — skipTOC for root (Python behavior)
        lines.push(makeMarkdownLinkedHeader(headerLevel, title, ctx, tmo.isRoot(), tmo));

        if ((tmo as any).version) {
            // Preserve ".0" for numeric versions (YAML 1.0 → JS number 1, Python float 1.0)
            let versionStr = String((tmo as any).version);
            if (typeof (tmo as any).version === 'number' && Number.isInteger((tmo as any).version)) {
                versionStr = ((tmo as any).version as number).toFixed(1);
            }
            lines.push(`Version: ${versionStr}\n`);
        }
        if ((tmo as any).status) {
            lines.push(`Status: ${(tmo as any).status}\n`);
        }
        if (toc) {
            lines.push(`Last update: ${new Date().toISOString().split('T')[0]} ${new Date().toTimeString().split(' ')[0]}\n`);
        }
        if (tmo.originDict.authors) {
            if (Array.isArray(tmo.originDict.authors)) {
                lines.push(`Authors: ${tmo.originDict.authors}\n`);
            } else {
                lines.push(`Authors: ${tmo.originDict.authors}\n`);
            }
        }
        if ((tmo as any).versionsFilterStr) {
            lines.push(`Versions in scope: ${(tmo as any).versionsFilterStr}\n`);
        }

        if (toc) {
            lines.push(PAGEBREAK);
            lines.push(makeMarkdownLinkedHeader(headerLevel + 1, 'Table of contents', ctx, true));
            lines.push('<div markdown="1">\n\n__TOC_PLACEHOLDER__\n\n</div>');
            lines.push(PAGEBREAK);
        }

        // Re-enable numbering after title/TOC (Python pattern)
        if (defaultEnabled && tmo.isRoot()) {
            enableHeadingNumbering();
        }

        // Executive Summary + Threats Summary
        // Python: header_level = header_level - 1 (PERMANENTLY modifies for the rest of function)
        if (summary) {
            if (toc) {
                headerLevel = headerLevel - 1;
            }
            lines.push(executiveSummary(tmo, headerLevel, ctx));
            lines.push(PAGEBREAK);
            lines.push(threatsSummary(tmo, headerLevel + 1, ctx));
        }

        // Scope
        lines.push(makeMarkdownLinkedHeader(headerLevel + 1, `${tmo.title} - scope of analysis`, ctx));

        // Overview
        if (tmo.scope && tmo.scope.description) {
            lines.push(makeMarkdownLinkedHeader(headerLevel + 2, `${tmo.title} Overview`, ctx));
            lines.push(tmo.scope.description);
        }

        // References
        if (tmo.scope && (tmo.scope as any).references) {
            lines.push(makeMarkdownLinkedHeader(headerLevel + 2, 'References', ctx));
            for (const ref of (tmo.scope as any).references) {
                lines.push(`- ${ref}`);
            }
        }

        // Security Objectives
        if (tmo.securityObjectives.length > 0) {
            lines.push(renderSecurityObjectives(tmo, headerLevel + 2, ctx));
        }

        // Inherited security objectives
        if (ancestorData && tmo.parent !== null) {
            const parentTmo = tmo.parent as ThreatModel;
            lines.push(makeMarkdownLinkedHeader(headerLevel + 2, 'Security Objectives inherited from other threat models', ctx));
            if (parentTmo.securityObjectives && parentTmo.securityObjectives.length > 0) {
                // Would render parent sec objs here
            } else {
                lines.push('No Security Objective inherited');
            }
        }

        // Linked threat models (descendants)
        const descendants = tmo.getDescendantsTM();
        if (descendants.length > 0) {
            lines.push(renderLinkedThreatModels(tmo, headerLevel + 2, ctx));
        }

        // Diagrams
        if (tmo.scope && (tmo.scope as any).diagram) {
            lines.push(makeMarkdownLinkedHeader(headerLevel + 2, 'Diagrams', ctx));
            lines.push((tmo.scope as any).diagram);
        }

        // Attackers
        if (tmo.attackers.length > 0) {
            lines.push(renderAttackers(tmo, headerLevel + 2, ctx));
        }

        // Inherited attackers
        if (ancestorData && tmo.parent !== null) {
            const parentTmo = tmo.parent as ThreatModel;
            if (parentTmo.getAllAttackers && parentTmo.getAllAttackers().length > 0) {
                lines.push(makeMarkdownLinkedHeader(headerLevel + 2, 'Actors inherited from other threat models', ctx));
                // Would render parent attackers
            }
        }

        // Assumptions
        if (tmo.assumptions.length > 0) {
            lines.push(renderAssumptions(tmo, headerLevel + 2, ctx));
        }

        // Assets
        if (tmo.assets.length > 0) {
            lines.push(renderAssets(tmo, headerLevel + 2, ctx));
        }

        // Analysis
        if (tmo.analysis && tmo.analysis.trim().length > 5) {
            lines.push('<hr/>');
            lines.push(makeMarkdownLinkedHeader(headerLevel + 1, `${tmo.title} Analysis`, ctx));
            lines.push(tmo.analysis);
        }

        // Attack tree + Threats
        if (tmo.threats.length > 0) {
            lines.push('<hr/>');
            lines.push(makeMarkdownLinkedHeader(headerLevel + 1, `${tmo.title} Attack tree`, ctx));
            lines.push(`<object type="image/svg+xml" style="width:100%; height:auto;" data="img/${id}_ATTACKTREE.svg">`);
            lines.push(`                     <img src="img/${id}_ATTACKTREE.svg" alt="$${tmo.title} attack tree" style="width:600; height:auto;" />`);
            lines.push(`                     </object>`);
            lines.push('<img src="img/legend_AttackTree.svg" width="600"/>');
            lines.push(PAGEBREAK);
            lines.push('<hr/>');

            lines.push(renderThreats(tmo, headerLevel + 1, ctx));
        }

        lines.push(PAGEBREAK);

        // Release history
        if ((tmo as any).history) {
            lines.push('**Release history**');
            lines.push((tmo as any).history);
        }

        lines.push('</div>');
        return lines.join('\n');
    }

    /**
     * Generate TOC matching Python's createTableOfContent().
     * 
     * Python logic:
     * - Scans headings line by line
     * - Skips lines with 'skipTOC'
     * - H1 (<2) = **bold**, H2 (==2) = ***bold-italic***, H3-H4 = plain, H5+ = skip
     * - Indentation: &nbsp;&nbsp; per heading level + "  " separator
     * - Blank line (\n\n) after each entry
     * - Keeps <code> tags in titles
     */
    private static generateTOC(markdown: string): string {
        let toc = '';
        const SKIP_TOC = 'skipTOC';
        const levelLimit = 4;
        
        const lines = markdown.split('\n');
        for (const line of lines) {
            // Check for heading lines
            const headingMatch = line.match(/^(#+)\s/);
            if (!headingMatch) continue;
            if (line.includes(SKIP_TOC)) continue;
            
            const level = headingMatch[1].length;
            if (level > levelLimit) continue;
            
            // Get full title (everything after the hashes + space)
            let fullTitle = line.replace(/^#+\s*/, '');
            
            // Extract anchor from existing <a id='...'></a> or <a name='...'></a>
            const anchorRegex = /\s*<a\s+(?:name|id)\s*=\s*['"]([^'"]+)['"][^>]*>\s*<\/a>\s*$/i;
            const anchorMatch = fullTitle.match(anchorRegex);
            let anchor = '';
            let titleText = '';
            
            if (anchorMatch) {
                anchor = anchorMatch[1];
                titleText = fullTitle.replace(anchorRegex, '').trimEnd();
            } else {
                titleText = fullTitle.trim();
                anchor = createTitleAnchorHash(titleText);
            }
            
            // Build TOC link (keep <code> tags in display text, matching Python)
            const tocLink = `[${titleText}](#${anchor}){.tocLink}`;
            
            // Format based on heading level (matching Python):
            // level < 2 (i.e., H1) → **bold**
            // level == 2 (H2) → ***bold-italic***
            // level 3-4 → plain
            let entry: string;
            if (level < 2) {
                entry = `**${tocLink}**`;
            } else if (level === 2) {
                entry = `***${tocLink}***`;
            } else {
                entry = tocLink;
            }
            
            // Indentation: Python replaces each # with &nbsp;&nbsp;
            // then adds space + explicit space before entry
            const tabs = '&nbsp;&nbsp;'.repeat(level);
            
            toc += `${tabs}  ${entry}\n\n`;
        }
        
        return toc;
    }

    private static generatePlantUML(tmo: ThreatModel, outputDir: string): void {
        const id = (tmo as any)._id || tmo.id;
        // Generate attack tree
        const attackTree = AttackTreeGenerator.generate(tmo);
        const pumlPath = path.join(outputDir, 'img', `${id}_ATTACKTREE.puml`);
        fs.writeFileSync(pumlPath, attackTree, 'utf8');
        console.log(`Generated: ${pumlPath}`);
    }
}
