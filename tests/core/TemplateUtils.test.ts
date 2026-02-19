import test from 'node:test';
import assert from 'node:assert';
import { makeMarkdownLinkedHeader } from '../../src/utils/TemplateUtils.js';

test('makeMarkdownLinkedHeader uses inline skipTOC marker', () => {
    const heading = makeMarkdownLinkedHeader(1, 'Sample Title', {}, true);

    assert.ok(heading.includes("<span class='skipTOC'></span>"));
    assert.ok(!heading.includes("<div class='skipTOC'></div>"));
});
