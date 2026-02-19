import test from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { marked } from 'marked';
import { load } from 'cheerio';
import ThreatModel from '../../src/models/ThreatModel.js';
import { ReportGenerator } from '../../src/ReportGenerator.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const fullFeatureYaml = path.join(__dirname, '..', 'exampleThreatModels', 'FullFeature', 'FullFeature.yaml');

function renderMarkdownWithMdInHtml(mdSource: string): string {
    const render = (src: string): string => marked.parse(src, { gfm: true, breaks: false, async: false }) as string;
    let html = render(mdSource);

    for (let pass = 0; pass < 8; pass++) {
        const $ = load(`<root>${html}</root>`, { decodeEntities: false });
        const nodes = $('*[markdown="1"], *[markdown="block"]');
        if (nodes.length === 0) {
            return $('root').html() || html;
        }

        nodes.each((_, element) => {
            const inner = $(element).html() || '';
            const renderedInner = render(inner).trim();
            $(element).removeAttr('markdown');
            $(element).html(renderedInner);
        });

        const next = $('root').html() || html;
        if (next === html) {
            break;
        }
        html = next;
    }

    return html;
}

function stripMarkdownAttributes(html: string): string {
    return html.replace(/\s+markdown=("|')(?:1|block)\1/g, '');
}

test('Generated HTML headings do not contain div.skipTOC', () => {
    if (!fs.existsSync(fullFeatureYaml)) {
        console.warn('FullFeature example not found, skipping HTML parsing integration test');
        return;
    }

    const outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tm-html-parse-'));
    try {
        const tmo = new ThreatModel(fullFeatureYaml);
        ReportGenerator.generate(tmo, 'TM_templateMKDOCS', outDir, {
            process_toc: true,
            process_prepost_md: true,
            process_heading_numbering: true,
        });

        const modelId = (tmo as any)._id || tmo.id;
        const mdPath = path.join(outDir, `${modelId}.md`);
        assert.ok(fs.existsSync(mdPath), 'Expected generated markdown report');

        const mdReport = fs.readFileSync(mdPath, 'utf8');
        assert.ok(!mdReport.includes("<div class='skipTOC'></div>"), 'Legacy block skipTOC marker should not be generated');

        const htmlBody = stripMarkdownAttributes(renderMarkdownWithMdInHtml(mdReport));
        const $ = load(`<root>${htmlBody}</root>`, { decodeEntities: false });

        $('h1,h2,h3,h4,h5,h6').each((_, h) => {
            assert.equal($(h).find('div.skipTOC').length, 0, 'Heading should not contain block skipTOC div');
        });
    } finally {
        fs.rmSync(outDir, { recursive: true, force: true });
    }
});
