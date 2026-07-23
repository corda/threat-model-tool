import test from 'node:test';
import assert from 'node:assert';
import { TMCVSS } from '../src/models/CVSS.js';

test('TMCVSS.clean_vector', async (t) => {
    await t.test('strips CVSS:3.1/ prefix', () => {
        const cvss = new TMCVSS('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
        assert.strictEqual(cvss.clean_vector(), 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
    });

    await t.test('strips CVSS:3.0/ prefix', () => {
        const cvss = new TMCVSS('CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
        assert.strictEqual(cvss.clean_vector(), 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
    });

    await t.test('strips unknown CVSS: prefix versions', () => {
        const cvss = new TMCVSS('CVSS:4.0/AV:N/AC:L');
        assert.strictEqual(cvss.clean_vector(), 'AV:N/AC:L');
    });

    await t.test('returns vector unchanged when there is no CVSS: prefix', () => {
        const cvss = new TMCVSS('AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
        assert.strictEqual(cvss.clean_vector(), 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
    });

    await t.test('returns empty string when vector is empty', () => {
        const cvss = new TMCVSS('');
        assert.strictEqual(cvss.clean_vector(), '');
    });

    await t.test('output never starts with the CVSS:x.x/ prefix', () => {
        for (const v of [
            'CVSS:3.0/AV:N/AC:L',
            'CVSS:3.1/AV:N/AC:L',
            'CVSS:4.0/AV:N/AC:L',
        ]) {
            const out = new TMCVSS(v).clean_vector();
            assert.ok(!out.startsWith('CVSS:'), `clean_vector should drop the CVSS: prefix, got: ${out}`);
        }
    });
});
