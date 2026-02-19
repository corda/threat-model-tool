import test from 'node:test';
import assert from 'node:assert';
import { HeadingNumberer } from '../../src/utils/HeadingNumberer.js';

test('HeadingNumberer defaults to topLevel=1', () => {
    // Markdown example (default topLevel=1):
    //   # Intro  -> 1
    //   ## Scope -> 1.1, 1.2 ...
    const numberer = HeadingNumberer.getInstance();
    HeadingNumberer.enable();
    numberer.reset();

    assert.equal(numberer.getNumber(1), '1');
    assert.equal(numberer.getNumber(2), '1.1');
    assert.equal(numberer.getNumber(2), '1.2');
});

test('HeadingNumberer supports custom topLevel', () => {
    // Markdown example (topLevel=2):
    //   ## Executive Summary -> 1
    //   ### Threats Summary  -> 1.1
    //   ## Scope             -> 2
    const numberer = HeadingNumberer.getInstance();
    HeadingNumberer.enable();
    numberer.reset();

    assert.equal(numberer.getNumber(2, 2), '1');
    assert.equal(numberer.getNumber(3, 2), '1.1');
    assert.equal(numberer.getNumber(2, 2), '2');
});
