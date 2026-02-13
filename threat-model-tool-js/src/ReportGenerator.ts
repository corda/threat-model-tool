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
import { HeadingNumberer, resetHeadingNumbers } from './utils/HeadingNumberer.js';
import { makeMarkdownLinkedHeader, createTitleAnchorHash } from './utils/TemplateUtils.js';

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

        // Render report
        let mdReport = this.renderFullReport(tmo, context);

        // Inject TOC
        if (context.processToc) {
            const toc = this.generateTOC(mdReport);
            mdReport = mdReport.replace('__TOC_PLACEHOLDER__', toc);
        }

        // Write markdown file
        fs.writeFileSync(mdOutFileName, mdReport, 'utf8');
        console.log(`Generated: ${mdOutFileName}`);

        // Generate PlantUML diagrams
        this.generatePlantUML(tmo, outputDir);
    }

    private static renderFullReport(tmo: ThreatModel, ctx: any): string {
        const lines: string[] = [];
        const id = (tmo as any)._id || tmo.id;
        const isChild = !!ctx.isChild;
        
        // Opening div
        if (!isChild) {
            lines.push("<div markdown=\"block\" class='current'>\n\n");
        }

        // Title
        if (!isChild) {
            const title = ctx.mainTitle || `${tmo.title} Threat Model`;
            lines.push(makeMarkdownLinkedHeader(1, title, ctx, true));
            lines.push(`\nVersion: ${tmo.originDict.version || '1.0'}\n`);
            lines.push(`Last update: ${new Date().toISOString().split('T')[0].replace(/-/g, '-')} ${new Date().toTimeString().split(' ')[0]}\n`);
            
            if (tmo.originDict.authors) {
               if (Array.isArray(tmo.originDict.authors)) {
                   lines.push(`Authors: ${tmo.originDict.authors.join('\n')}\n`);
               } else {
                   lines.push(`Authors: ${tmo.originDict.authors}\n`);
               }
            }

            lines.push('\n<div class="pagebreak"></div>\n\n');

            // TOC placeholder
            lines.push(makeMarkdownLinkedHeader(2, "Table of contents", ctx, true));
            lines.push('__TOC_PLACEHOLDER__\n');
            lines.push('<div class="pagebreak"></div>\n\n');

            // Executive Summary
            lines.push(executiveSummary(tmo, 0, ctx));
            lines.push('<div class="pagebreak"></div>\n\n');

            // Threats Summary
            lines.push(threatsSummary(tmo, 0, ctx));
        }

        // Scope section
        lines.push(makeMarkdownLinkedHeader(1, `${tmo.title} - scope of analysis`, ctx));
        
        // Overview
        if (tmo.scope && tmo.scope.description) {
            lines.push(makeMarkdownLinkedHeader(2, `${tmo.title} Overview`, ctx));
            lines.push(tmo.scope.description);
            lines.push('\n\n');
        } else if (tmo.originDict.scope?.description) {
            lines.push(makeMarkdownLinkedHeader(2, `${tmo.title} Overview`, ctx));
            lines.push(tmo.originDict.scope.description);
            lines.push('\n\n');
        }

        // Security Objectives
        lines.push(renderSecurityObjectives(tmo, 2, ctx));

        // Linked threat models
        lines.push(renderLinkedThreatModels(tmo, 2, ctx));

        // Attackers
        lines.push(renderAttackers(tmo, 2, ctx));

        // Assumptions
        lines.push(renderAssumptions(tmo, 2, ctx));

        // Assets
        lines.push(renderAssets(tmo, 2, ctx));

        // Attack tree summary
        lines.push(makeMarkdownLinkedHeader(1, `${tmo.title} Attack tree`, ctx));
        lines.push(`<img src="img/${id}_ATTACKTREE.svg"/>\n\n`);

        // Threats section
        lines.push(renderThreats(tmo, 1, ctx));

        // Process children models recursively for their own sections
        for (const child of tmo.children) {
            if (child instanceof ThreatModel) {
                lines.push(this.renderFullReport(child, { ...ctx, isChild: true, mainTitle: `${child.title} Threat Model Section` }));
            }
        }

        if (!isChild) {
            lines.push(renderAnnexes(tmo, 0, ctx));
        }

        if (!isChild) {
            lines.push('\n</div>');
        }
        return lines.join('\n');
    }

    private static generateTOC(markdown: string): string {
        const lines: string[] = [];
        lines.push('<div markdown="1">\n');
        
        // Parse headings
        const headingRegex = /^(#{1,6})\s+((?:\d+\.)*\d+)?\s*(.*)$/gm;
        let match;
        
        while ((match = headingRegex.exec(markdown)) !== null) {
            const hashes = match[1];
            const level = hashes.length;
            const number = match[2] || '';
            let fullTitleLine = match[3].trim();
            
            if (fullTitleLine.includes('skipTOC')) continue;
            
            // Extract anchor if exists: <a id='...'></a>
            let anchor = '';
            const anchorMatch = fullTitleLine.match(/<a\s+id='([^']+)'>/);
            if (anchorMatch) {
                anchor = anchorMatch[1];
                // Remove anchor and skipTOC from title
                fullTitleLine = fullTitleLine.replace(/<a\s+id='([^']+)'>.*$/, '').trim();
                fullTitleLine = fullTitleLine.replace(/<div class='skipTOC'><\/div>/, '').trim();
            } else {
                anchor = createTitleAnchorHash(fullTitleLine);
            }
            
            // Clean title for TOC (remove tags like <code>)
            const displayTitleText = fullTitleLine.replace(/<[^>]+>/g, '').trim();
            
            const indent = '&nbsp;&nbsp;'.repeat(Math.max(0, level - 1));
            const bold = level <= 2 ? '**' : level === 3 ? '***' : '';
            const displayTitle = number ? `${number} ${displayTitleText}` : displayTitleText;
            
            lines.push(`${indent}  ${bold}[${displayTitle}](#${anchor}){.tocLink}${bold}\n`);
        }

        lines.push('\n</div>');
        return lines.join('');
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
