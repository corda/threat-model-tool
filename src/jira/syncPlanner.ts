import { markdownToAdf, sanitizeDescriptionMarkdown } from './syncAdf.js';
import type { CsvThreatRow, PlanResult, PlannedJiraUpdate } from './syncTypes.js';

export interface PlanSyncOptions {
    manualMap?: Record<string, string>;
    includeOnlyCreateTicketYes?: boolean;
}

function shouldIncludeByCreateTicket(row: CsvThreatRow, strict: boolean): boolean {
    if (!strict) {
        return true;
    }

    const flag = (row['Create Ticket'] ?? '').trim().toLowerCase();
    return flag === '' || flag === 'yes';
}

export function planCsvSyncUpdates(
    rows: CsvThreatRow[],
    threatToTicketMap: Record<string, string>,
    options: PlanSyncOptions = {},
): PlanResult {
    const strictCreateTicket = options.includeOnlyCreateTicketYes ?? true;
    const resolvedMap: Record<string, string> = {
        ...threatToTicketMap,
        ...(options.manualMap ?? {}),
    };

    const updates: PlannedJiraUpdate[] = [];
    const skipped: Array<{ row: number; reason: string }> = [];
    const seenIssueKeys = new Set<string>();

    rows.forEach((row, index) => {
        const rowNumber = index + 1;

        if (!shouldIncludeByCreateTicket(row, strictCreateTicket)) {
            skipped.push({ row: rowNumber, reason: 'create-ticket-filtered' });
            return;
        }

        const threatId = (row['Threat ID'] ?? '').trim();
        if (!threatId) {
            skipped.push({ row: rowNumber, reason: 'missing-threat-id' });
            return;
        }

        const issueKey = resolvedMap[threatId];
        if (!issueKey) {
            skipped.push({ row: rowNumber, reason: `unmapped-threat-id:${threatId}` });
            return;
        }

        if (seenIssueKeys.has(issueKey)) {
            skipped.push({ row: rowNumber, reason: `duplicate-issue-key:${issueKey}` });
            return;
        }
        seenIssueKeys.add(issueKey);

        const summary = (row.Summary ?? '').trim();
        const descriptionMarkdown = sanitizeDescriptionMarkdown(row.Description ?? '');

        if (!summary) {
            skipped.push({ row: rowNumber, reason: 'missing-summary' });
            return;
        }

        if (!descriptionMarkdown.trim()) {
            skipped.push({ row: rowNumber, reason: 'missing-description' });
            return;
        }

        updates.push({
            issueKey,
            threatId,
            summary,
            descriptionMarkdown,
            descriptionAdf: markdownToAdf(descriptionMarkdown),
        });
    });

    return { updates, skipped };
}
