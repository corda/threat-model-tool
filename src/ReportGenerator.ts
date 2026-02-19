import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
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
    renderAnnexes,
    renderOperationalHardening,
    renderKeysSummary,
    renderISO27001Summary,
    renderTestingGuide
} from './renderers/lib_py.js';
import { AttackTreeGenerator } from './puml/AttackTreeGenerator.js';
import { HeadingNumberer, resetHeadingNumbers, disableHeadingNumbering, enableHeadingNumbering, isHeadingNumberingEnabled } from './utils/HeadingNumberer.js';
import { makeMarkdownLinkedHeader, createTitleAnchorHash, PAGEBREAK } from './utils/TemplateUtils.js';

export class ReportGenerator {
    private static TEMPLATE_MAPPING: Record<string, (tmo: ThreatModel, ctx: any) => string> = {
        'TM_templateFull': (tmo, ctx) => ReportGenerator.renderFullReport(tmo, ctx),
        'TM_templateMKDOCS': (tmo, ctx) => ReportGenerator.renderMKDOCSReport(tmo, ctx),
        'MKdocs': (tmo, ctx) => ReportGenerator.renderMKDOCSReport(tmo, ctx),
        'TM_templateNoTocNoSummary': (tmo, ctx) => ReportGenerator.renderCompactReport(tmo, ctx),
        'full': (tmo, ctx) => ReportGenerator.renderFullReport(tmo, ctx),
        'TM_template': (tmo, ctx) => ReportGenerator.renderFullReport(tmo, ctx),
    };

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

        // Copy static assets (TM assets + Python legend PUML assets) for parity
        this.copyStaticAssets(tmo, outputDir);

        // Reset heading numbers
        enableHeadingNumbering();
        resetHeadingNumbers();

        const hasPrePostSections = fs.existsSync(path.join(tmo.assetDir(), 'markdown_sections_1'));

        // Set context defaults
        const context = {
            processToc: true,
            process_toc: true,
            process_prepost_md: true,
            process_heading_numbering: true,
            rootHeaderLevel: hasPrePostSections ? 2 : 1,
            mainTitle: ctx.mainTitle || null,
            ...ctx
        };

        // Render report using the Python-aligned pipeline
        let mdReport = this.renderTemplateByName(template, tmo, context);

        // Inject pre/post markdown sections from assets/markdown_sections_1 when present
        mdReport = this.injectPrePostMarkdownSections(tmo, mdReport, context);

        // Apply Python-style heading numbering pass after TOC placeholder
        mdReport = this.applyHeadingNumberingPass(mdReport, context);

        // Inject TOC
        if ((context.process_toc ?? context.processToc ?? true)) {
            mdReport = this.createTableOfContent(mdReport);
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

    private static injectPrePostMarkdownSections(tmo: ThreatModel, mdReport: string, ctx: any): string {
        if (!(ctx.process_prepost_md ?? true)) {
            return mdReport;
        }

        const sectionsDir = path.join(tmo.assetDir(), 'markdown_sections_1');
        if (!fs.existsSync(sectionsDir) || !fs.statSync(sectionsDir).isDirectory()) {
            return mdReport;
        }

        mdReport = mdReport.replace('__TOC_PLACEHOLDER__', '');
        mdReport = mdReport.replace(/^\s*#\s*table\s+of\s+content\s*\r?\n?/gim, '');
        mdReport = mdReport.replace(/(?:<div\s+[^>]*class=["']pagebreak["'][^>]*>\s*<\/div>\s*){2,}/gi, '<div class="pagebreak"></div>\n');

        const files = fs.readdirSync(sectionsDir);
        const preFiles = files
            .filter((fileName) => /^pre_\d\d_.*\.md$/i.test(fileName))
            .sort()
            .reverse();
        const postFiles = files
            .filter((fileName) => /^post_\d\d_.*\.md$/i.test(fileName))
            .sort();

        for (const fileName of preFiles) {
            const filePath = path.join(sectionsDir, fileName);
            mdReport = fs.readFileSync(filePath, 'utf8') + '\n' + mdReport;
        }

        for (const fileName of postFiles) {
            const filePath = path.join(sectionsDir, fileName);
            mdReport = mdReport + '\n' + fs.readFileSync(filePath, 'utf8');
        }

        return mdReport;
    }

    private static applyHeadingNumberingPass(mdReport: string, ctx: any): string {
        if (!(ctx.process_heading_numbering ?? true)) {
            return mdReport;
        }

        const numberer = HeadingNumberer.getInstance();
        numberer.reset();

        const outputLines: string[] = [];
        let inFence = false;
        let numberStarted = false;

        // Which markdown heading depth is considered numbering level "1".
        // Default is 1 (H1 starts at 1), but callers can override via context.
        //
        // Example (topLevel=2):
        //   ## Executive Summary  -> 1
        //   ### Threats Summary   -> 1.1
        // This prevents legacy "0.1" prefixes when the first numbered heading is H2.
        const topLevel = Number.isInteger(ctx.heading_numbering_top_level)
            ? Number(ctx.heading_numbering_top_level)
            : Number(ctx.rootHeaderLevel ?? 1);

        const fencePattern = /^\s*(```|~~~)/;
        const headingPattern = /^(#{1,6})\s+(.*)$/;
        const alreadyNumberedPattern = /^\d+(?:[\.\d]*\s*-?\s*)/;

        for (const line of mdReport.split('\n')) {
            if (fencePattern.test(line)) {
                inFence = !inFence;
                outputLines.push(line);
                continue;
            }

            if (!numberStarted) {
                if (line.includes('__TOC_PLACEHOLDER__') || (ctx.process_prepost_md === false)) {
                    numberStarted = true;
                }
                outputLines.push(line);
                continue;
            }

            if (inFence) {
                outputLines.push(line);
                continue;
            }

            const headingMatch = line.match(headingPattern);
            if (!headingMatch) {
                outputLines.push(line);
                continue;
            }

            const hashes = headingMatch[1];
            const title = headingMatch[2].trim();
            if (alreadyNumberedPattern.test(title)) {
                outputLines.push(line);
                continue;
            }

            const headingLevel = hashes.length;
            const number = numberer.getNumber(headingLevel, topLevel);
            if (!number) {
                outputLines.push(line);
                continue;
            }

            outputLines.push(`${hashes} ${number} ${title}`);
        }

        return outputLines.join('\n');
    }

    /**
     * Render a full report matching Python render_full_report():
     * - render_tm_report_part(root, ancestor_data=True, toc=True, summary=True)
     * - render_tm_report_part(each descendant, ancestor_data=False)
     * - Annex 1: Operational Hardening
     * - Annex 2: Keys Classification
     * - (optional: ISO27001 Summary)
     */
    /**
     * Dispatcher to render template by name.
     */
    private static renderTemplateByName(name: string, tmo: ThreatModel, ctx: any): string {
        const renderer = this.TEMPLATE_MAPPING[name] || this.TEMPLATE_MAPPING['full'];
        return renderer(tmo, ctx);
    }

    private static renderFullReport(tmo: ThreatModel, ctx: any): string {
        resetHeadingNumbers();
        const lines: string[] = [];
        const rootHeaderLevel = ctx.rootHeaderLevel || 1;

        // Root part: with TOC and summary
        lines.push(this.renderTmReportPart(tmo, true, true, true, rootHeaderLevel, ctx));

        // Descendants
        for (const descendant of tmo.getDescendantsTM()) {
            lines.push(this.renderTmReportPart(descendant, false, false, false, rootHeaderLevel, ctx));
        }

        // Annexes
        lines.push(renderAnnexes(tmo, rootHeaderLevel, ctx));

        return lines.join('\n');
    }

    private static renderMKDOCSReport(tmo: ThreatModel, ctx: any): string {
        resetHeadingNumbers();
        ctx.useMarkDown_attr_list_ext = ctx.useMarkDown_attr_list_ext ?? true;
        ctx.process_toc = false;
        ctx.process_prepost_md = false;

        const lines: string[] = [];
        const rootHeaderLevel = ctx.rootHeaderLevel || 1;

        // Root part: no TOC, with summary
        lines.push(this.renderTmReportPart(tmo, true, false, true, rootHeaderLevel, ctx));

        // Descendants
        for (const descendant of tmo.getDescendantsTM()) {
            // Descendants keep base + 1 for consistency
            lines.push(this.renderTmReportPart(descendant, false, false, false, rootHeaderLevel + 1, ctx));
        }

        // Additional sections for MKDOCS
        lines.push(makeMarkdownLinkedHeader(rootHeaderLevel + 1, "Requests For Information", ctx));
        lines.push("__RFI_PLACEHOLDER__");
        lines.push(PAGEBREAK);
        lines.push(renderOperationalHardening(tmo, rootHeaderLevel + 1, ctx));
        lines.push(PAGEBREAK);
        lines.push(renderTestingGuide(tmo, rootHeaderLevel + 1, ctx));
        lines.push(PAGEBREAK);
        lines.push(renderKeysSummary(tmo, rootHeaderLevel + 1, ctx));

        // ISO27001 Summary (if applicable)
        if ((tmo as any).ISO27001Ref) {
            lines.push(PAGEBREAK);
            lines.push(renderISO27001Summary(tmo, rootHeaderLevel + 1, ctx));
        }

        return lines.join('\n');
    }

    private static renderCompactReport(tmo: ThreatModel, ctx: any): string {
        const lines: string[] = [];
        const rootHeaderLevel = ctx.rootHeaderLevel || 1;

        // Root part: no TOC, no summary, header + 1
        lines.push(this.renderTmReportPart(tmo, true, false, false, rootHeaderLevel + 1, ctx));

        // Descendants: header level remains base
        for (const descendant of tmo.getDescendantsTM()) {
            lines.push(this.renderTmReportPart(descendant, false, false, false, rootHeaderLevel, ctx));
        }

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
            if (parentTmo.attackers && parentTmo.attackers.length > 0) {
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
            lines.push('<div markdown="1">');
            lines.push('**Release history**');
            lines.push((tmo as any).history);
            lines.push('</div>');
        }

        lines.push('</div>');
        return lines.join('\n');
    }

    private static transformNamedAnchorMd(text: string): string {
        const pattern = /^(.*?)(?:\s*<a\s+(?:name|id)\s*=\s*['"]([^'"]+)['"][^>]*>\s*<\/a>\s*)$/s;
        const match = text.match(pattern);
        if (!match) {
            return text;
        }
        const titleText = match[1].trimEnd();
        const anchor = match[2];
        return `<a href="#${anchor}" class="tocLink">${titleText}</a>`;
    }

    private static createTableOfContent(mdData: string, levelLimit: number = 4): string {
        let toc = '';
        const newLines: string[] = [];
        const skipToc = 'skipTOC';

        for (const line of mdData.split('\n')) {
            if (line.includes('__TOC_PLACEHOLDER__')) {
                newLines.push('__TOC_PLACEHOLDER__');
                continue;
            }

            if (/^#+\s/.test(line) && !line.includes(skipToc)) {
                const title = line.replace(/#/g, '').trim();
                const anchorPattern = /<a\s+(?:name|id)\s*=\s*['"][^'"]+['"][^>]*>\s*<\/a>/i;

                let modifiedLine = line;
                let titleWithAnchor = title;

                if (!anchorPattern.test(line)) {
                    const anchorName = createTitleAnchorHash(title);
                    const anchorHtml = ` <a name='${anchorName}' class='tocLink'></a>`;
                    modifiedLine = line + anchorHtml;
                    titleWithAnchor = title + anchorHtml;
                }

                newLines.push(modifiedLine);

                const tocTitle = this.transformNamedAnchorMd(titleWithAnchor);
                const levelMatch = line.match(/^(#+)\s/);
                if (!levelMatch) {
                    continue;
                }
                const level = levelMatch[1].length;
                if (level > levelLimit) {
                    continue;
                }

                let tocEntry: string;
                if (level < 2) {
                    tocEntry = `**${tocTitle}**`;
                } else if (level === 2) {
                    tocEntry = `***${tocTitle}***`;
                } else {
                    tocEntry = tocTitle;
                }

                const tabs = '&nbsp;&nbsp;'.repeat(level);
                toc += `${tabs}  ${tocEntry}\n\n`;
            } else {
                newLines.push(line);
            }
        }

        const withAnchors = newLines.join('\n');
        return withAnchors.replace('__TOC_PLACEHOLDER__', toc);
    }

    private static generatePlantUML(tmo: ThreatModel, outputDir: string): void {
        const id = (tmo as any)._id || tmo.id;
        const imgDir = path.join(outputDir, 'img');
        const threatTreeDir = path.join(imgDir, 'threatTree');
        const secObjDir = path.join(imgDir, 'secObjectives');

        fs.mkdirSync(imgDir, { recursive: true });
        fs.mkdirSync(threatTreeDir, { recursive: true });
        fs.mkdirSync(secObjDir, { recursive: true });

        const allModels = [tmo, ...tmo.getDescendantsTM()];

        for (const model of allModels) {
            const modelId = (model as any)._id || model.id;
            const perTmAttackTree = AttackTreeGenerator.generate(model);
            const perTmPath = path.join(imgDir, `${modelId}_ATTACKTREE.puml`);
            fs.writeFileSync(perTmPath, perTmAttackTree, 'utf8');
            console.log(`Generated: ${perTmPath}`);
        }

        const completeAttackTree = AttackTreeGenerator.generateComplete(tmo);
        const completePath = path.join(imgDir, `COMPLETE_${id}_ATTACKTREE.puml`);
        fs.writeFileSync(completePath, completeAttackTree, 'utf8');
        console.log(`Generated: ${completePath}`);

        for (const threat of AttackTreeGenerator.getAllThreats(tmo)) {
            const threatId = (threat as any)._id || threat.id;
            const threatTree = AttackTreeGenerator.generatePerThreat(threat);
            const threatPath = path.join(threatTreeDir, `${threatId}.puml`);
            fs.writeFileSync(threatPath, threatTree, 'utf8');
            console.log(`Generated: ${threatPath}`);
        }

        for (const secObj of AttackTreeGenerator.getAllSecurityObjectives(tmo)) {
            const secObjId = (secObj as any)._id || secObj.id;
            const secObjTree = AttackTreeGenerator.generateSecObjectiveTree(tmo, secObj);
            const secObjPath = path.join(secObjDir, `${secObjId}.puml`);
            fs.writeFileSync(secObjPath, secObjTree, 'utf8');
            console.log(`Generated: ${secObjPath}`);
        }

        const secObjectivesOverview = AttackTreeGenerator.generateSecObjectivesOverview(tmo);
        const secObjectivesOverviewPath = path.join(imgDir, 'secObjectives.puml');
        fs.writeFileSync(secObjectivesOverviewPath, secObjectivesOverview, 'utf8');
        console.log(`Generated: ${secObjectivesOverviewPath}`);
    }

    private static copyStaticAssets(tmo: ThreatModel, outputDir: string): void {
        const models = [tmo, ...tmo.getDescendantsTM()];
        for (const model of models) {
            const assetDir = model.assetDir();
            if (fs.existsSync(assetDir) && fs.statSync(assetDir).isDirectory()) {
                fs.cpSync(assetDir, outputDir, { recursive: true, force: true });
            }
        }

        // Resolve the Python asset folder relative to this package (not process.cwd()).
        // When this tool is invoked from another repo (e.g. `threat-modeling`) process.cwd()
        // points to the consumer and the previous code failed to find Python assets.
        const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
        const pythonAssetRootDir = path.join(packageRoot, 'src', 'r3threatmodeling', 'assets');
        for (const subdir of ['css', 'img', 'js']) {
            const srcDir = path.join(pythonAssetRootDir, subdir);
            const dstDir = path.join(outputDir, subdir);
            if (fs.existsSync(srcDir) && fs.statSync(srcDir).isDirectory()) {
                fs.mkdirSync(dstDir, { recursive: true });
                fs.cpSync(srcDir, dstDir, { recursive: true, force: true });
            }
        }

        const pythonAssetImgDir = path.join(pythonAssetRootDir, 'img');
        const outImgDir = path.join(outputDir, 'img');
        if (fs.existsSync(pythonAssetImgDir) && fs.statSync(pythonAssetImgDir).isDirectory()) {
            for (const fileName of ['legend_AttackTree.puml', 'legend_SecObjTree.puml']) {
                const srcFile = path.join(pythonAssetImgDir, fileName);
                if (fs.existsSync(srcFile)) {
                    fs.mkdirSync(outImgDir, { recursive: true });
                    fs.copyFileSync(srcFile, path.join(outImgDir, fileName));
                }
            }
        }
    }
}
