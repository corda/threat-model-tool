/**
 * Core Jira-ticket-creation workflows ported from the Python tool.
 *
 * Two modes:
 *   • reviewRisk  – builds a URL that opens the Jira "create issue" form in a browser
 *   • createIssue – creates the issue programmatically via the REST API
 */

import { JiraClient, type JiraConfig } from './jiraClient.js';
import { JiraProjectIssueType, JiraFields } from './jiraProject.js';
import {
    threatDescription,
    riskDescription,
    mapCvssToImpact,
    riskRating,
    treatmentPlanDate,
    formatJiraDate,
} from './jiraFormatters.js';
import type Threat from '../models/Threat.js';

// Re-export for convenience
export { JiraClient, type JiraConfig } from './jiraClient.js';
export { JiraProjectIssueType, JiraFields } from './jiraProject.js';
export * from './jiraFormatters.js';
export * from './syncTypes.js';
export * from './syncAdf.js';
export * from './syncCsv.js';
export * from './syncMapping.js';
export * from './syncPlanner.js';

/**
 * Build a URL that opens the Jira "create issue" form, pre-populated with
 * threat data. Matches the Python `review_jira_for_threat` function.
 */
export async function buildReviewUrl(
    client: JiraClient,
    projectKey: string,
    issueTypeName: string,
    threat: Threat,
    tmHome: string,
): Promise<string> {
    const project = await JiraProjectIssueType.fetch(client, projectKey, issueTypeName);
    const fields = new JiraFields(
        {
            pid: project.projectId,
            issuetype: project.issueTypeId,
            summary: threat.title,
            description: threatDescription(threat, false, tmHome),
            labels: 'Design-Issue',
        },
        project.fieldMap,
    );

    const cvss = threat.cvssObject;
    if (cvss) {
        fields.set('CVSS Score', String(cvss.getSmartScoreVal()));
        fields.set('CVSS Vector', cvss.clean_vector());
        const sevId = project.idForFieldValue('Severity', cvss.getSmartScoreSeverity());
        if (sevId) fields.set('Severity', sevId);
    }

    const params = new URLSearchParams();
    for (const [k, v] of Object.entries(fields.toRecord())) {
        params.set(k, String(v));
    }
    const baseUrl = client['baseUrl'] as string; // access private for URL only
    return `${baseUrl}/secure/CreateIssueDetails!init.jspa?${params}`;
}

/**
 * Build a URL for a *risk*-style Jira issue, pre-populated with threat data.
 * Matches the Python `review_risk_for_threat` function.
 */
export async function buildRiskReviewUrl(
    client: JiraClient,
    projectKey: string,
    issueTypeName: string,
    threat: Threat,
    tmHome: string,
    extraFields: Record<string, string> = {},
): Promise<string> {
    const project = await JiraProjectIssueType.fetch(client, projectKey, issueTypeName);
    const fields = new JiraFields(
        {
            pid: project.projectId,
            issuetype: project.issueTypeId,
            summary: `[R3TM] ${threat.title}`,
            description: riskDescription(threat, false, tmHome),
            labels: 'Design-Issue',
        },
        project.fieldMap,
        project.fieldValueMap,
    );

    const rr = riskRating(threat.getSmartScoreDesc(), 3);
    const severity = threat.cvssObject ? threat.cvssObject.getSmartScoreSeverity() : 'None';
    fields.set('Impact', mapCvssToImpact(severity));
    fields.set('Impact Description', threat.impact_desc);
    fields.set('Risk Type', 'Security Risk');
    fields.set('Target Date for Closure', formatJiraDate(treatmentPlanDate(rr)));
    fields.set('Incident Reported By (if not the person raising the ticket)', 'R3 Threat Model');
    fields.set('Likelihood', '3 - Possible');

    for (const [k, v] of Object.entries(extraFields)) {
        fields.set(k, v);
        console.log(`Adding: ${k} (${v})`);
    }

    const params = new URLSearchParams();
    for (const [k, v] of Object.entries(fields.toRecord())) {
        params.set(k, String(v));
    }
    const baseUrl = client['baseUrl'] as string;
    return `${baseUrl}/secure/CreateIssueDetails!init.jspa?${params}`;
}

/**
 * Create a Jira issue programmatically via the REST API.
 * Matches the Python `create_jira_for_threat` function.
 */
export async function createJiraForThreat(
    client: JiraClient,
    projectKey: string,
    issueTypeName: string,
    threat: Threat,
): Promise<string> {
    const project = await JiraProjectIssueType.fetch(client, projectKey, issueTypeName);
    const fields: Record<string, unknown> = {
        project: { key: projectKey },
        issuetype: { name: issueTypeName },
        summary: threat.title,
        description: threatDescription(threat, true),
    };

    const cvss = threat.cvssObject;
    if (cvss) {
        const fmap = project.fieldMap;
        if (fmap['CVSS Score'])  fields[fmap['CVSS Score']]  = cvss.getSmartScoreVal();
        if (fmap['CVSS Vector']) fields[fmap['CVSS Vector']] = cvss.clean_vector();
        if (fmap['Severity'])    fields[fmap['Severity']]    = { value: cvss.getSmartScoreSeverity() };
    }

    const issue = await client.createIssue(fields);
    return issue.key;
}
