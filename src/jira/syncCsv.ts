import type { CsvThreatRow } from './syncTypes.js';

export function normalizeCsvKey(key: string): string {
    return key.replace(/\ufeff/g, '').trim().replace(/^"|"$/g, '');
}

export function normalizeCsvRow(row: Record<string, string | undefined>): CsvThreatRow {
    const normalized: CsvThreatRow = {};
    for (const [key, value] of Object.entries(row)) {
        normalized[normalizeCsvKey(key)] = (value ?? '').trim();
    }
    return normalized;
}
