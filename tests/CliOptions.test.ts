import { describe, it } from 'node:test';
import assert from 'node:assert';
import { parseFlag, parseOption, parseMultiOption } from '../src/scripts/cli-options.js';

describe('parseFlag', () => {
    it('matches long form --flag', () => {
        assert.strictEqual(parseFlag(['--help'], 'help'), true);
        assert.strictEqual(parseFlag(['--TMDirectory', './x', '--generatePDF'], 'generatePDF'), true);
    });

    it('matches single-dash short form for single-character flags', () => {
        assert.strictEqual(parseFlag(['-h'], 'h'), true);
        assert.strictEqual(parseFlag(['some-arg', '-h'], 'h'), true);
    });

    it('does not match single-dash form for multi-character flags', () => {
        // Avoid matching `-help` as if it were `--help` to prevent ambiguity
        // with bundled short flags or unrelated arguments.
        assert.strictEqual(parseFlag(['-help'], 'help'), false);
        assert.strictEqual(parseFlag(['-generatePDF'], 'generatePDF'), false);
    });

    it('returns false when flag is absent', () => {
        assert.strictEqual(parseFlag(['--other'], 'help'), false);
        assert.strictEqual(parseFlag([], 'h'), false);
    });
});

describe('parseOption', () => {
    it('returns the value following --flag', () => {
        assert.strictEqual(parseOption(['--TMDirectory', './path'], 'TMDirectory'), './path');
    });

    it('returns undefined when flag is missing', () => {
        assert.strictEqual(parseOption(['--other', 'val'], 'TMDirectory'), undefined);
    });

    it('returns undefined when next arg is itself a flag', () => {
        assert.strictEqual(parseOption(['--TMDirectory', '--other'], 'TMDirectory'), undefined);
    });

    it('returns undefined when --flag is the last argument', () => {
        assert.strictEqual(parseOption(['--TMDirectory'], 'TMDirectory'), undefined);
    });
});

describe('parseMultiOption', () => {
    it('collects values from repeated --flag value pairs', () => {
        assert.deepStrictEqual(
            parseMultiOption(['--assetFolder', 'a', '--assetFolder', 'b'], 'assetFolder'),
            ['a', 'b'],
        );
    });

    it('supports --flag=value syntax', () => {
        assert.deepStrictEqual(
            parseMultiOption(['--assetFolder=a', '--assetFolder=b'], 'assetFolder'),
            ['a', 'b'],
        );
    });

    it('splits comma-separated values and trims whitespace', () => {
        assert.deepStrictEqual(
            parseMultiOption(['--assetFolder', 'a, b , c'], 'assetFolder'),
            ['a', 'b', 'c'],
        );
    });

    it('returns empty array when flag is absent', () => {
        assert.deepStrictEqual(parseMultiOption(['--other', 'x'], 'assetFolder'), []);
    });
});
