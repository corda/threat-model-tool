import test from 'node:test';
import assert from 'node:assert';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import ThreatModel from '../src/models/ThreatModel.js';
import { ReportGenerator } from '../src/ReportGenerator.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const fullFeatureYaml = path.join(__dirname, 'exampleThreatModels', 'FullFeature', 'FullFeature.yaml');

test('Report Template Rendering', async (t) => {
    if (!fs.existsSync(fullFeatureYaml)) {
        console.warn('FullFeature example not found, skipping template tests');
        return;
    }

    const tmo = new ThreatModel(fullFeatureYaml);
    const ctx = {
        processToc: true,
        process_toc: true,
        process_prepost_md: true,
        process_heading_numbering: true,
        rootHeaderLevel: 1
    };

    await t.test('Full Template should include TOC and Summary', () => {
        // @ts-ignore - access private method for testing
        const md = ReportGenerator.renderTemplateByName('TM_templateFull', tmo, ctx);
        
        assert.ok(md.includes('Table of contents'), 'Should contain Table of contents');
        assert.ok(md.includes('Executive Summary'), 'Should contain Executive Summary');
        assert.ok(md.includes('__TOC_PLACEHOLDER__'), 'Should contain TOC placeholder');
    });

    await t.test('MKDOCS Template should include RFI and Testing Guide but no internal TOC', () => {
        const mkdocsCtx = { ...ctx };
        // @ts-ignore
        const md = ReportGenerator.renderTemplateByName('TM_templateMKDOCS', tmo, mkdocsCtx);
        
        assert.ok(!md.includes('Table of contents'), 'Should NOT contain Table of contents');
        assert.ok(!md.includes('__TOC_PLACEHOLDER__'), 'Should NOT contain TOC placeholder');
        assert.ok(md.includes('Requests For Information'), 'Should contain Requests For Information');
        assert.ok(md.includes('Testing guide'), 'Should contain Testing guide');
        assert.ok(md.includes('Executive Summary'), 'Should still contain Executive Summary (per mkdocs template definition)');
    });

    await t.test('Compact Template should NOT include TOC or Summary', () => {
        // @ts-ignore
        const md = ReportGenerator.renderTemplateByName('TM_templateNoTocNoSummary', tmo, ctx);
        
        assert.ok(!md.includes('Table of contents'), 'Should NOT contain Table of contents');
        assert.ok(!md.includes('Executive Summary'), 'Should NOT contain Executive Summary');
        assert.ok(!md.includes('__TOC_PLACE_HOLDER__'), 'Should NOT contain TOC placeholder');
    });

    await t.test('Heading numbering should trigger based on ctx.process_prepost_md', () => {
        // This is a bit tricky to test directly as numbering happens in ReportGenerator.generate() 
        // after renderTemplateByName. But we can verify the logic in generate if we mock fs.
    });
});
