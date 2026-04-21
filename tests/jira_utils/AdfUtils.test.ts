import assert from 'node:assert';
import test from 'node:test';

import { adfTextLines, markdownToAdf, sanitizeDescriptionMarkdown } from '../../src/jira/syncAdf.js';

test('sanitizeDescriptionMarkdown removes leading Description heading', () => {
    const input = '**Description**\n\nAttack details here';
    const output = sanitizeDescriptionMarkdown(input);
    assert.equal(output, 'Attack details here');
});

test('markdownToAdf builds a valid ADF document and supports simple formatting', () => {
    const doc = markdownToAdf('Hello **World**\n\n- item one\n- item two');

    assert.equal(doc.type, 'doc');
    assert.equal(doc.version, 1);
    assert.ok(doc.content.length >= 2);

    const lines = adfTextLines(doc);
    assert.ok(lines.includes('Hello'));
    assert.ok(lines.includes('World'));
    assert.ok(lines.includes('item one'));
    assert.ok(lines.includes('item two'));
});
