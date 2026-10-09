import test from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import ThreatModel from '../../src/models/ThreatModel.js';
import { ReportGenerator } from '../../src/ReportGenerator.js';
import { displayName, renderAnnexFolder, collectModelIds, collectAnchors } from '../../src/utils/AnnexRenderer.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const fixtureDir = path.join(__dirname, '..', 'fixtures', 'annexes', 'AnnexExample');
const fixtureYaml = path.join(fixtureDir, 'AnnexExample.yaml');
const annexesDir = path.join(fixtureDir, 'assets', 'annexes');
const example1Yaml = path.join(__dirname, '..', 'exampleThreatModels', 'Example1', 'Example1.yaml');

function withTempDir<T>(run: (dir: string) => T): T {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tm-annexes-'));
    try {
        return run(dir);
    } finally {
        fs.rmSync(dir, { recursive: true, force: true });
    }
}

function render(dir: string, overrides: Record<string, unknown> = {}) {
    return renderAnnexFolder({
        annexesDir,
        outputDir: dir,
        firstNumber: 3,
        headerLevel: 2,
        useAttrListAnchors: false,
        knownIds: collectModelIds([fixtureYaml]),
        ...overrides,
    });
}

test('displayName drops number prefixes and extensions', () => {
    assert.equal(displayName('20-playbooks'), 'Playbooks');
    assert.equal(displayName('10_incident-response-plan'), 'Incident response plan');
    assert.equal(displayName('00-overview.md'), 'Overview');
    assert.equal(displayName('PB-01-first.md'), 'PB 01 first');
});

test('annex folders become numbered annexes, ordered by number prefix', () => {
    withTempDir((dir) => {
        const { markdown, fileCount } = render(dir);
        assert.equal(fileCount, 4);
        const plan = markdown.indexOf('## Annex 3: Response Plan');
        const playbooks = markdown.indexOf('## Annex 4: Playbooks');
        assert.ok(plan >= 0 && playbooks > plan, 'annexes are numbered from firstNumber in folder order');
        assert.ok(markdown.includes("<a id='annex-10-response-plan'></a>"));
        assert.ok(markdown.includes('This annex holds the plan documents.'), '_index.md intro is rendered');
    });
});

test('file titles sit under the annex and headings are shifted, with manual numbers stripped', () => {
    withTempDir((dir) => {
        const { markdown } = render(dir);
        assert.ok(markdown.includes('### Plan Overview'));
        assert.ok(markdown.includes('#### Purpose'), '"## 1. Purpose" becomes a level-4 heading without its number');
        assert.ok(!markdown.includes('1. Purpose'));
        assert.ok(markdown.includes('### PB-02 Second playbook'));
        assert.ok(markdown.includes('### Sub-area') || markdown.includes('### Sub area'), 'a sub-folder is a heading');
        assert.ok(markdown.includes('#### Notes'), 'a file in a sub-folder sits one level deeper');
    });
});

test('body headings are kept out of the table of contents', () => {
    withTempDir((dir) => {
        const { markdown } = render(dir);
        assert.ok(/#### Purpose <span class='skipTOC'><\/span>/.test(markdown));
        assert.ok(!/### Plan Overview <span class='skipTOC'>/.test(markdown), 'file titles stay in the table of contents');
    });
});

test('links between annex files become in-report anchors', () => {
    withTempDir((dir) => {
        const { markdown } = render(dir);
        assert.ok(markdown.includes('[first playbook](#annex-20-playbooks-pb-01-first)'));
        assert.ok(markdown.includes('[the notes](#annex-20-playbooks-sub-area-notes)'), 'a #fragment is dropped');
        assert.ok(markdown.includes('[overview](#annex-10-response-plan-00-overview)'));
        assert.ok(markdown.includes('[example](https://example.com/page)'), 'external links are untouched');
        assert.ok(!markdown.includes('](../'), 'no relative file link is left outside code');
    });
});

test('MkDocs anchors use the attr_list syntax', () => {
    withTempDir((dir) => {
        const { markdown } = render(dir, { useAttrListAnchors: true });
        assert.ok(markdown.includes('## Annex 3: Response Plan {#annex-10-response-plan}'));
    });
});

test('a linked .puml becomes an image and is copied where PlantUML renders it', () => {
    withTempDir((dir) => {
        const { markdown } = render(dir);
        assert.ok(markdown.includes('![Swimlane diagram](img/annexes/20-playbooks/PB-01-first.svg)'));
        assert.ok(fs.existsSync(path.join(dir, 'img', 'annexes', '20-playbooks', 'PB-01-first.puml')));
    });
});

test('broken links and unknown IDs are reported, code fences are ignored', () => {
    withTempDir((dir) => {
        const result = render(dir);
        assert.equal(result.linkWarnings.length, 1);
        assert.match(result.linkWarnings[0], /PB-99-missing\.md/);
        assert.deepEqual(result.idWarnings.map(w => /`(\w+)`/.exec(w)?.[1]), ['NOT_IN_THE_MODEL']);
        assert.ok(result.markdown.includes('## this is not a heading'), 'fenced text is left as written');
    });
});

test('full report: annexes are appended once, anchors resolve, raw files are not copied', () => {
    withTempDir((dir) => {
        ReportGenerator.generate(new ThreatModel(fixtureYaml), 'full', dir, { skipDiagrams: true });
        const md = fs.readFileSync(path.join(dir, 'AnnexExample.md'), 'utf8');

        assert.equal(md.split('Annex 3: Response Plan').length - 1, 2, 'once as a heading and once in the table of contents');
        for (const target of md.matchAll(/\]\(#(annex-[a-z0-9-]+)\)/g)) {
            assert.ok(md.includes(`<a id='${target[1]}'></a>`), `anchor exists for ${target[1]}`);
        }
        assert.ok(!fs.existsSync(path.join(dir, 'annexes')), 'assets/annexes is not published as raw files');
        assert.ok(fs.existsSync(path.join(dir, 'img', 'annexes', '20-playbooks', 'PB-01-first.puml')));
    });
});

test('MkDocs report: annexes are numbered from 1 and use attr_list anchors', () => {
    withTempDir((dir) => {
        ReportGenerator.generate(new ThreatModel(fixtureYaml), 'MKdocs', dir, { skipDiagrams: true, process_toc: false });
        const md = fs.readFileSync(path.join(dir, 'AnnexExample.md'), 'utf8');
        assert.ok(/Annex 1: Response Plan \{#annex-10-response-plan\}/.test(md));
        assert.ok(md.includes('(#annex-20-playbooks-pb-01-first)'));
    });
});

test('annexes can be switched off, and are left out of public reports', () => {
    withTempDir((dir) => {
        ReportGenerator.generate(new ThreatModel(fixtureYaml), 'full', dir, { skipDiagrams: true, process_annexes: false });
        assert.ok(!fs.readFileSync(path.join(dir, 'AnnexExample.md'), 'utf8').includes('Annex 3'));
    });
    withTempDir((dir) => {
        const tmo = new ThreatModel(fixtureYaml);
        (tmo as any)._visibility = 'public';
        ReportGenerator.generate(tmo, 'full', dir, { skipDiagrams: true });
        assert.ok(!fs.readFileSync(path.join(dir, 'AnnexExample.md'), 'utf8').includes('Annex 3'));
    });
});

test('strictAnnexes fails the build on a broken link', () => {
    withTempDir((dir) => {
        assert.throws(
            () => ReportGenerator.generate(new ThreatModel(fixtureYaml), 'full', dir, { skipDiagrams: true, strictAnnexes: true }),
            /Annex check failed/
        );
    });
});

test('a model without an annexes folder is not affected', () => {
    withTempDir((dir) => {
        const before = path.join(dir, 'before');
        const after = path.join(dir, 'after');
        ReportGenerator.generate(new ThreatModel(example1Yaml), 'full', before, { skipDiagrams: true });
        ReportGenerator.generate(new ThreatModel(example1Yaml), 'full', after, { skipDiagrams: true, process_annexes: false });
        assert.equal(
            fs.readFileSync(path.join(before, 'Example1.md'), 'utf8'),
            fs.readFileSync(path.join(after, 'Example1.md'), 'utf8')
        );
    });
});

test('backticked model IDs with an anchor in the report become links; others and code fences stay plain', () => {
    withTempDir((dir) => {
        const { markdown } = render(dir, { linkTargets: new Set(['DATA_EXPOSURE', 'ACCESS_CONTROL_ENFORCEMENT']) });
        assert.ok(markdown.includes('[`DATA_EXPOSURE`](#DATA_EXPOSURE)'));
        assert.ok(markdown.includes('[`ACCESS_CONTROL_ENFORCEMENT`](#ACCESS_CONTROL_ENFORCEMENT)'));
        assert.ok(markdown.includes('`NOT_IN_THE_MODEL`') && !markdown.includes('[`NOT_IN_THE_MODEL`]'), 'an ID without an anchor stays plain');
        assert.ok(markdown.includes('`ALSO_NOT_CHECKED`') && !markdown.includes('[`ALSO_NOT_CHECKED`]'), 'code fences are never linked');
    });
});

test('an ID that is already the text of a link is not linked twice', () => {
    withTempDir((dir) => {
        const folder = path.join(dir, 'annexes', '10-a');
        fs.mkdirSync(folder, { recursive: true });
        fs.writeFileSync(path.join(folder, 'doc.md'), '# Doc\n\nSee [`DATA_EXPOSURE`](https://example.com) and `DATA_EXPOSURE`.\n');
        const { markdown } = renderAnnexFolder({
            annexesDir: path.join(dir, 'annexes'), outputDir: dir, firstNumber: 1, headerLevel: 2,
            useAttrListAnchors: false, linkTargets: new Set(['DATA_EXPOSURE']),
        });
        assert.ok(markdown.includes('[`DATA_EXPOSURE`](https://example.com)'));
        assert.ok(markdown.includes('and [`DATA_EXPOSURE`](#DATA_EXPOSURE).'));
    });
});

test('collectAnchors finds html and MkDocs anchors', () => {
    const anchors = collectAnchors("## T <a id='THREAT_ONE'></a>\n\n<dt id='CM_ONE'>x</dt> ### H {#ASSET_ONE}");
    assert.deepEqual([...anchors].sort(), ['ASSET_ONE', 'CM_ONE', 'THREAT_ONE']);
});

test('full report: model IDs in the annexes link to threats and countermeasures that have anchors', () => {
    withTempDir((dir) => {
        ReportGenerator.generate(new ThreatModel(fixtureYaml), 'full', dir, { skipDiagrams: true });
        const md = fs.readFileSync(path.join(dir, 'AnnexExample.md'), 'utf8');
        assert.ok(md.includes("<dt id='ACCESS_CONTROL_ENFORCEMENT'>"), 'countermeasures have an anchor');
        assert.ok(md.includes('[`ACCESS_CONTROL_ENFORCEMENT`](#ACCESS_CONTROL_ENFORCEMENT)'));
        assert.ok(md.includes('[`DATA_EXPOSURE`](#DATA_EXPOSURE)'));
        assert.ok(md.includes('`NOT_IN_THE_MODEL`') && !md.includes('[`NOT_IN_THE_MODEL`]'));
    });
});
