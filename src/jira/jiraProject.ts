/**
 * JiraProjectIssueType – wraps Jira create-metadata for a project + issue type,
 * providing field-name → field-key mappings and allowed-value lookups.
 *
 * TypeScript port of the Python `JiraProjectIssueType` class.
 */

import type { CreateMeta, CreateMetaField, JiraClient } from './jiraClient.js';

export class JiraProjectIssueType {
    private meta: CreateMeta;

    constructor(meta: CreateMeta) {
        this.meta = meta;
    }

    static async fetch(client: JiraClient, projectKey: string, issueTypeName: string): Promise<JiraProjectIssueType> {
        const meta = await client.getCreateMeta(projectKey, issueTypeName);
        if (!meta.projects?.length) {
            throw new Error(`Unable to find project ${projectKey} or issue type ${issueTypeName}`);
        }
        return new JiraProjectIssueType(meta);
    }

    get projectId(): string {
        return this.meta.projects[0].id;
    }

    get issueTypeId(): string {
        return this.meta.projects[0].issuetypes[0].id;
    }

    private get fields(): Record<string, CreateMetaField> {
        return this.meta.projects[0].issuetypes[0].fields;
    }

    /**
     * Map of field display-name → field key (e.g. "CVSS Score" → "customfield_10042").
     */
    get fieldMap(): Record<string, string> {
        const map: Record<string, string> = {};
        for (const field of Object.values(this.fields)) {
            map[field.name] = field.key;
        }
        return map;
    }

    /**
     * Map of field display-name → { allowedValue → id }.
     */
    get fieldValueMap(): Record<string, Record<string, string>> {
        const result: Record<string, Record<string, string>> = {};
        for (const fieldDef of Object.values(this.fields)) {
            const schema = fieldDef.schema ?? {};
            if (!fieldDef.allowedValues) continue;

            if (schema.type === 'option') {
                result[fieldDef.name] = Object.fromEntries(
                    fieldDef.allowedValues.map(v => [v.value ?? v.name ?? '', v.id])
                );
            } else if (schema.type === 'array') {
                result[fieldDef.name] = Object.fromEntries(
                    fieldDef.allowedValues.map(v => [v.name ?? v.value ?? '', v.id])
                );
            }
        }
        return result;
    }

    /**
     * Look up the id for a specific allowed value of a named field.
     */
    idForFieldValue(fieldName: string, value: string): string | undefined {
        const fmap = this.fieldMap;
        const key = fmap[fieldName];
        if (!key) return undefined;
        const field = this.fields[key];
        if (!field?.allowedValues) return undefined;
        const found = field.allowedValues.find(v => v.value === value);
        return found?.id;
    }
}

/**
 * JiraFields – dict-like builder that translates human-readable field names
 * and allowed-value labels to Jira internal keys/ids.
 */
export class JiraFields {
    private data: Record<string, unknown> = {};
    private fieldMap: Record<string, string>;
    private valueMap: Record<string, Record<string, string>>;

    constructor(
        init: Record<string, unknown>,
        fieldMap: Record<string, string>,
        valueMap: Record<string, Record<string, string>> = {},
    ) {
        this.fieldMap = fieldMap;
        this.valueMap = valueMap;
        // Copy initial values without translation
        for (const [k, v] of Object.entries(init)) {
            this.data[k] = v;
        }
    }

    set(key: string, value: unknown): void {
        // Translate value via allowed-value map
        if (typeof value === 'string' && this.valueMap[key]?.[value]) {
            value = this.valueMap[key][value];
        }

        // Translate key name
        if (this.fieldMap[key]) {
            const translatedKey = this.fieldMap[key].toLowerCase();
            console.log(`Copying: ${translatedKey} (${String(value)})`);
            this.data[translatedKey] = value;
        } else {
            console.log(`Missing: ${key} (not copied)`);
        }
    }

    toRecord(): Record<string, unknown> {
        return { ...this.data };
    }
}
