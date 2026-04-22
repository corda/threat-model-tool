export interface CsvThreatRow {
    [key: string]: string;
}

export interface AdfNode {
    type: string;
    attrs?: Record<string, unknown>;
    text?: string;
    marks?: Array<{ type: string; attrs?: Record<string, unknown> }>;
    content?: AdfNode[];
}

export interface AdfDocument {
    type: 'doc';
    version: 1;
    content: AdfNode[];
}

export interface PlannedJiraUpdate {
    issueKey: string;
    threatId: string;
    summary: string;
    descriptionMarkdown: string;
    descriptionAdf: AdfDocument;
}

export interface PlanResult {
    updates: PlannedJiraUpdate[];
    skipped: Array<{ row: number; reason: string }>;
}
