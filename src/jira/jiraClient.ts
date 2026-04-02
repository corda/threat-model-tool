/**
 * Jira client wrapper — thin adapter over the Jira REST API v2.
 *
 * This is a minimal, dependency-light client that uses native `fetch` (Node 18+)
 * instead of pulling in a heavy Jira SDK.
 *
 * Environment / constructor config:
 *   ATLASSIAN_URI      – e.g. https://your-org.atlassian.net
 *   ATLASSIAN_USERNAME – Jira email
 *   ATLASSIAN_PASSWORD – Jira API token (NOT your password)
 */

export interface JiraConfig {
    baseUrl: string;
    username: string;
    token: string;
}

export interface CreateMeta {
    projects: CreateMetaProject[];
}

export interface CreateMetaProject {
    id: string;
    key: string;
    issuetypes: CreateMetaIssueType[];
}

export interface CreateMetaIssueType {
    id: string;
    name: string;
    fields: Record<string, CreateMetaField>;
}

export interface CreateMetaField {
    key: string;
    name: string;
    schema: { type: string; items?: string; custom?: string };
    allowedValues?: { id: string; value?: string; name?: string }[];
}

export class JiraClient {
    private authHeader: string;
    private baseUrl: string;

    constructor(config: JiraConfig) {
        this.baseUrl = config.baseUrl.replace(/\/+$/, '');
        this.authHeader = 'Basic ' + Buffer.from(`${config.username}:${config.token}`).toString('base64');
    }

    private async request<T>(path: string, init?: RequestInit): Promise<T> {
        const url = `${this.baseUrl}/rest/api/2${path}`;
        const res = await fetch(url, {
            ...init,
            headers: {
                'Authorization': this.authHeader,
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                ...(init?.headers ?? {}),
            },
        });
        if (!res.ok) {
            const body = await res.text();
            throw new Error(`Jira API ${res.status}: ${body}`);
        }
        return res.json() as Promise<T>;
    }

    async getCreateMeta(projectKey: string, issueTypeName: string): Promise<CreateMeta> {
        const params = new URLSearchParams({
            projectKeys: projectKey,
            issuetypeNames: issueTypeName,
            expand: 'projects.issuetypes.fields',
        });
        return this.request<CreateMeta>(`/issue/createmeta?${params}`);
    }

    async createIssue(fields: Record<string, unknown>): Promise<{ key: string; id: string; self: string }> {
        return this.request('/issue', {
            method: 'POST',
            body: JSON.stringify({ fields }),
        });
    }
}
