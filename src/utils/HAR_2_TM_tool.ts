import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import yaml from 'js-yaml';

export type SequenceFormat = 'plantuml' | 'mermaid';
export type SequenceView = 'sequence' | 'HighLevelDFD';

export interface TrustBoundaryConfig {
    name: string;
    participants: string[];
    color?: string;
}

export interface TrustBoundaryCatalogEntry {
    ID: string;
    title?: string;
    color?: string;
}

export interface CollapseParticipantConfig {
    name: string;
    participants: string[];
}

export type ParticipantPropertyValue = string | number | boolean | string[];

export interface ParticipantPropertyConfig {
    participants: string[];
    properties: Record<string, ParticipantPropertyValue>;
}

export interface ParticipantConfig {
    ID: string;
    title?: string;
    domains?: string[];
    trustBoundary?: string;
    properties?: Record<string, ParticipantPropertyValue>;
    collapseTo?: string;
    inScope?: boolean;
}

export interface RenderingConfig {
    view?: SequenceView;
    genericCallDescription?: string;
    includeSourceHostInLabel?: boolean;
    singleCallPerSourceHost?: boolean;
    singleCallPerParticipant?: boolean;
}

export interface Har2SeqConfig {
    browserParticipant?: string;
    participantFilter?: string[];
    participants?: string[];
    excludePaths?: string[];
    messagePrefixes?: Record<string, string>;
    trustBoundaries?: TrustBoundaryConfig[];
    collapseParticipants?: CollapseParticipantConfig[];
    condenseParticipants?: CollapseParticipantConfig[];
    participantProperties?: ParticipantPropertyConfig[];
}

interface StarterHar2SeqConfig {
    browserParticipant: string;
    excludePaths: string[];
    messagePrefixes: Record<string, string>;
    trustBoundaries: TrustBoundaryCatalogEntry[];
    participants: ParticipantConfig[];
}

export interface HarRequest {
    method: string;
    url: string;
}

export interface HarResponse {
    status: number;
}

export interface HarEntry {
    startedDateTime?: string;
    request: HarRequest;
    response: HarResponse;
}

export interface HarLog {
    entries: HarEntry[];
}

export interface HarFile {
    log: HarLog;
}

export interface Har2SeqOptions {
    browserParticipant?: string;
    includeActivation?: boolean;
    format?: SequenceFormat;
    view?: SequenceView;
    genericCallDescription?: string;
    includeSourceHostInLabel?: boolean;
    singleCallPerSourceHost?: boolean;
    singleCallPerParticipant?: boolean;
}

export interface HarIndexEntry {
    requestId: number;
    method: string;
    url: string;
    status: number;
    // host, path and startedDateTime are intentionally omitted from the index:
    // - host and path are derivable from `url`
    // - startedDateTime is redundant since entries are already in chronological order
    // entryOffset/entryLength are a byte range into the source .har: seek(entryOffset) and read
    // entryLength bytes to get this entry's full, untouched JSON (body included) in O(1), with no
    // sequential scan and no duplicated sidecar. See read_har_entry().
    entryOffset: number;
    entryLength: number;
}

export interface HarIndexFile {
    schemaVersion: 'indexHAR.v2';
    // Basename of the .har the byte offsets refer to (the index lives next to it).
    harFile: string;
    // Size and SHA-256 of the exact .har the byte offsets refer to. Use these to detect drift:
    // if the HAR is re-captured, offsets are invalid and the index must be regenerated.
    harBytes: number;
    harSha256: string;
    totalRequests: number;
    entries: HarIndexEntry[];
}

// On-disk v2 layout: a columnar table. The per-entry key names (method/url/status/offset/length)
// appear once in `columns` instead of being repeated on all N rows, and requestId is implicit
// (row index + 1, entries are in chronological order). This is materially fewer tokens for LLM
// workflows with no loss of information. load_indexHAR_file() expands it back to HarIndexEntry[].
const INDEX_V2_COLUMNS = ['method', 'url', 'status', 'offset', 'length'] as const;
type IndexV2Row = [string, string, number, number, number];
interface IndexHARv2OnDisk {
    schemaVersion: 'indexHAR.v2';
    harFile: string;
    harBytes: number;
    harSha256: string;
    totalRequests: number;
    columns: readonly string[];
    entries: IndexV2Row[];
}


export interface StarterConfigOptions {
    outputHarPath?: string;
    maxTopHosts?: number;
    firstPartyPatterns?: string[];
    collapseThirdParty?: boolean;
}

interface HostCountSummary {
    host: string;
    requestCount: number;
}

interface SequenceEvent {
    host: string;
    boundaryHost: string;
    path: string;
    method: string;
    status: number;
    startedDateTime?: string;
}

interface KnownParticipantCluster {
    id: string;
    name: string;
    patterns: string[];
    properties?: Record<string, ParticipantPropertyValue>;
}

const KNOWN_PARTICIPANT_CLUSTERS: KnownParticipantCluster[] = [
    {
        id: 'GOOGLE_EDGE_CDN',
        name: 'Google Edge/CDN',
        patterns: ['*.google.com', '*.google.it', '*.googleapis.com', '*.gstatic.com', '*.doubleclick.net', '*.googletagmanager.com'],
        properties: {
            authentication: 'none',
            authorization: 'public asset delivery',
            dataSensitivity: 'low',
            owner: 'third-party',
        },
    },
    {
        id: 'SOCIAL_ADS_NETWORK',
        name: 'Social / Ads Network',
        patterns: ['*.facebook.com', '*.tiktok.com', '*.tiktokw.us', '*.bing.com', '*.outbrain.com', '*.teads.tv', '*.criteo.com'],
        properties: {
            authentication: 'vendor managed',
            authorization: 'tracking / campaign scoped',
            dataSensitivity: 'marketing / telemetry',
            owner: 'third-party',
        },
    },
    {
        id: 'CONSENT_PRIVACY_PLATFORM',
        name: 'Consent / Privacy Platform',
        patterns: ['*.usercentrics.eu'],
        properties: {
            authentication: 'none',
            authorization: 'consent workflow scoped',
            dataSensitivity: 'consent / preference data',
            owner: 'third-party',
        },
    },
    {
        id: 'OBSERVABILITY_TELEMETRY',
        name: 'Observability / Telemetry',
        patterns: ['*.sentry.io', '*.clarity.ms'],
        properties: {
            authentication: 'vendor managed',
            authorization: 'telemetry ingestion scoped',
            dataSensitivity: 'diagnostic / telemetry',
            owner: 'third-party',
        },
    },
];

const MULTI_PART_SUFFIXES = new Set([
    'co.uk',
    'org.uk',
    'gov.uk',
    'com.au',
    'com.br',
    'com.mx',
    'co.nz',
    'co.jp',
]);

function parseUrl(urlString: string): { host: string; path: string } | null {
    try {
        const parsed = new URL(urlString);
        const host = parsed.host;
        const pathWithQuery = `${parsed.pathname}${parsed.search}`;
        const pathOnly = parsed.pathname || '/';
        return {
            host,
            path: pathWithQuery || pathOnly,
        };
    } catch {
        return null;
    }
}

function sortEntriesByStartedDateTime<T extends { startedDateTime?: string }>(entries: T[]): T[] {
    return [...entries].sort((a, b) => {
        if (!a.startedDateTime && !b.startedDateTime) return 0;
        if (!a.startedDateTime) return 1;
        if (!b.startedDateTime) return -1;

        const aTime = Date.parse(a.startedDateTime);
        const bTime = Date.parse(b.startedDateTime);

        if (Number.isNaN(aTime) || Number.isNaN(bTime)) {
            return 0;
        }

        return aTime - bTime;
    });
}

function normalizeEntries(entries: HarEntry[]): HarEntry[] {
    return sortEntriesByStartedDateTime(entries);
}

function isParticipantAllowed(host: string, participants: string[]): boolean {
    if (participants.length === 0) {
        return true;
    }
    return participants.some(rule => matchesBoundaryRule(host, rule));
}

function getParticipantFilter(config: Har2SeqConfig): string[] {
    return config.participantFilter ?? config.participants ?? [];
}

function collapseParticipantHost(host: string, rules: CollapseParticipantConfig[]): string {
    for (const rule of rules) {
        if (!rule.participants || rule.participants.length === 0) {
            continue;
        }

        if (rule.participants.some(rulePattern => matchesBoundaryRule(host, rulePattern))) {
            return rule.name;
        }
    }

    return host;
}

function getCollapseRules(config: Har2SeqConfig): CollapseParticipantConfig[] {
    return config.collapseParticipants ?? config.condenseParticipants ?? [];
}

function resolveRenderingConfig(options: Har2SeqOptions = {}): RenderingConfig {
    return {
        view: options.view,
        genericCallDescription: options.genericCallDescription,
        includeSourceHostInLabel: options.includeSourceHostInLabel,
        singleCallPerSourceHost: options.singleCallPerSourceHost,
        singleCallPerParticipant: options.singleCallPerParticipant,
    };
}

function resolveParticipantProperties(
    displayHost: string,
    sourceHost: string,
    propertyRules: ParticipantPropertyConfig[]
): Record<string, ParticipantPropertyValue> {
    const resolved: Record<string, ParticipantPropertyValue> = {};

    for (const rule of propertyRules) {
        if (!rule.participants || rule.participants.length === 0) {
            continue;
        }

        const matches = rule.participants.some(rulePattern =>
            matchesBoundaryRule(displayHost, rulePattern) || matchesBoundaryRule(sourceHost, rulePattern)
        );

        if (matches) {
            Object.assign(resolved, rule.properties);
        }
    }

    return resolved;
}

function formatPropertyValue(value: ParticipantPropertyValue): string {
    if (Array.isArray(value)) {
        return value.join(', ');
    }

    return String(value);
}

function wrapPlantUmlNoteLine(line: string, maxLength = 80): string[] {
    if (line.length <= maxLength) {
        return [line];
    }

    const indent = line.match(/^\s*/)?.[0] ?? '';
    const content = line.slice(indent.length).trim();
    if (!content) {
        return [line];
    }

    const words = content.split(/\s+/);
    const wrapped: string[] = [];
    let current = indent;

    for (const word of words) {
        const next = current.trim().length === 0 ? `${indent}${word}` : `${current} ${word}`;
        if (current.length > indent.length && next.length > maxLength) {
            wrapped.push(current);
            current = `${indent}${word}`;
            continue;
        }

        current = next;
    }

    if (current.length > 0) {
        wrapped.push(current);
    }

    return wrapped;
}

function renderPlantUmlParticipantNote(
    alias: string,
    properties: Record<string, ParticipantPropertyValue>,
    options: { backgroundColor?: string; hiddenHosts?: string[]; hiddenHostsLabel?: string; overParticipant?: boolean } = {}
): string[] {
    const entries = Object.entries(properties);
    const hiddenHosts = options.hiddenHosts ?? [];
    if (entries.length === 0 && hiddenHosts.length === 0) {
        return [];
    }

    const noteAnchor = options.overParticipant ? 'note over' : 'note right of';
    const noteHeader = options.backgroundColor
        ? `${noteAnchor} ${alias} ${options.backgroundColor}`
        : `${noteAnchor} ${alias}`;
    const lines = [noteHeader];

    if (hiddenHosts.length > 0) {
        if (options.hiddenHostsLabel) {
            lines.push(...wrapPlantUmlNoteLine(`  <b>${options.hiddenHostsLabel}:</b> ${hiddenHosts.join(', ')}`));
        } else {
            lines.push('  Hosts');
            for (const host of hiddenHosts) {
                lines.push(...wrapPlantUmlNoteLine(`  - ${host}`));
            }
        }
    }

    if (entries.length > 0) {
        if (hiddenHosts.length > 0) {
            lines.push('  ');
        }
        for (const [key, value] of entries) {
            lines.push(...wrapPlantUmlNoteLine(`  <b>${key}:</b> ${formatPropertyValue(value)}`));
        }
    }

    lines.push('end note');
    return lines;
}

function renderMermaidParticipantNote(alias: string, properties: Record<string, ParticipantPropertyValue>): string[] {
    const entries = Object.entries(properties);
    if (entries.length === 0) {
        return [];
    }

    const note = entries.map(([key, value]) => `${key}: ${formatPropertyValue(value)}`).join('<br/>');
    return [`    Note right of ${alias}: ${note}`];
}

function matchesBoundaryRule(host: string, rule: string): boolean {
    const trimmedRule = rule.trim();
    if (!trimmedRule) return false;

    if (host === trimmedRule) {
        return true;
    }

    const regexRule = toRegexRule(trimmedRule);
    if (regexRule) {
        return regexRule.test(host);
    }

    if (trimmedRule === '*') {
        return true;
    }

    if (trimmedRule.startsWith('http://') || trimmedRule.startsWith('https://')) {
        const parsed = parseUrl(trimmedRule);
        return parsed?.host === host;
    }

    if (trimmedRule.startsWith('/')) {
        return false;
    }

    if (trimmedRule.includes('/')) {
        return trimmedRule.startsWith(`${host}/`);
    }

    if (trimmedRule.startsWith('*.')) {
        const suffix = trimmedRule.slice(2);
        return host === suffix || host.endsWith(`.${suffix}`);
    }

    return false;
}

function toRegexRule(rule: string): RegExp | null {
    if (rule.startsWith('regex:')) {
        return new RegExp(rule.slice('regex:'.length));
    }

    const match = rule.match(/^\/(.*)\/([dgimsuvy]*)$/);
    if (!match) {
        return null;
    }

    return new RegExp(match[1], match[2]);
}

function isExcluded(host: string, pathName: string, excludePaths: string[]): boolean {
    if (excludePaths.length === 0) {
        return false;
    }

    return excludePaths.some(rule => {
        const trimmedRule = rule.trim();
        if (!trimmedRule) return false;

        if (trimmedRule.startsWith('/')) {
            return pathName.startsWith(trimmedRule);
        }

        if (trimmedRule.startsWith('http://') || trimmedRule.startsWith('https://')) {
            const parsed = parseUrl(trimmedRule);
            if (!parsed) return false;
            return parsed.host === host && pathName.startsWith(parsed.path);
        }

        if (trimmedRule.includes('/')) {
            return `${host}${pathName}`.startsWith(trimmedRule);
        }

        return host === trimmedRule;
    });
}

function toParticipantAlias(index: number): string {
    return `S${index + 1}`;
}

function escapeMermaidLabel(value: string): string {
    return value.replace(/"/g, '\\"');
}

function escapePlantUmlLabel(value: string): string {
    return value.replace(/"/g, '\\"');
}

function truncateRequestPath(pathValue: string, maxLength = 100): string {
    if (pathValue.length <= maxLength) {
        return pathValue;
    }

    const queryIndex = pathValue.indexOf('?');
    const basePath = queryIndex >= 0 ? pathValue.slice(0, queryIndex) : pathValue;

    if (basePath.length >= maxLength - 1) {
        return `${basePath.slice(0, maxLength - 1)}...`;
    }

    return `${basePath}?...`;
}

function buildRequestLabel(
    prefix: string,
    method: string,
    pathValue: string,
    displayHost?: string,
    sourceHost?: string,
    includeSourceHostInLabel = false,
): string {
    const truncatedPath = truncateRequestPath(pathValue);
    const showSourceHost = includeSourceHostInLabel && sourceHost && sourceHost !== displayHost;
    const target = showSourceHost ? `${sourceHost} ${truncatedPath}` : truncatedPath;
    return `${prefix}${method} ${target}`;
}

function buildHighLevelCallLabel(displayHost: string, genericCallDescription?: string): string {
    if (genericCallDescription) {
        return genericCallDescription;
    }

    return `Call to ${displayHost.toLowerCase()}`;
}

export function loadHarFile(harPath: string): HarFile {
    const fullPath = path.resolve(harPath);
    if (!fs.existsSync(fullPath)) {
        throw new Error(`HAR file not found: ${fullPath}`);
    }

    const raw = fs.readFileSync(fullPath, 'utf8');
    const parsed = JSON.parse(raw) as HarFile;

    if (!parsed.log || !Array.isArray(parsed.log.entries)) {
        throw new Error(`Invalid HAR format in ${fullPath}: missing log.entries[]`);
    }

    return parsed;
}

export function loadHar2SeqConfig(configPath: string): Har2SeqConfig {
    const fullPath = path.resolve(configPath);
    if (!fs.existsSync(fullPath)) {
        throw new Error(`Config file not found: ${fullPath}`);
    }

    const raw = fs.readFileSync(fullPath, 'utf8');
    const ext = path.extname(fullPath).toLowerCase();

    if (ext === '.yaml' || ext === '.yml') {
        const parsed = yaml.load(raw);
        if (!parsed || typeof parsed !== 'object') {
            return {};
        }
        return normalizeHar2SeqConfig(parsed as Record<string, unknown>);
    }

    if (ext === '.json') {
        return normalizeHar2SeqConfig(JSON.parse(raw) as Record<string, unknown>);
    }

    throw new Error(`Unsupported config extension: ${ext}. Use .yaml, .yml, or .json`);
}

function normalizeHar2SeqConfig(rawConfig: Record<string, unknown>): Har2SeqConfig {
    if (Array.isArray(rawConfig.participants)) {
        return normalizeParticipantCentricConfig(rawConfig);
    }

    return rawConfig as Har2SeqConfig;
}

function normalizeParticipantCentricConfig(rawConfig: Record<string, unknown>): Har2SeqConfig {
    const participants = Array.isArray(rawConfig.participants)
        ? rawConfig.participants.filter((item): item is ParticipantConfig => Boolean(item) && typeof item === 'object' && typeof (item as ParticipantConfig).ID === 'string')
        : [];
    const participantById = new Map(participants.map(participant => [participant.ID, participant]));
    const trustBoundaryCatalog = new Map<string, TrustBoundaryCatalogEntry>();

    for (const boundary of Array.isArray(rawConfig.trustBoundaries) ? rawConfig.trustBoundaries : []) {
        if (!boundary || typeof boundary !== 'object' || typeof (boundary as TrustBoundaryCatalogEntry).ID !== 'string') {
            continue;
        }

        const typedBoundary = boundary as TrustBoundaryCatalogEntry;
        trustBoundaryCatalog.set(typedBoundary.ID, typedBoundary);
    }

    const participantFilter: string[] = [];
    const collapseParticipants: CollapseParticipantConfig[] = [];
    const participantProperties: ParticipantPropertyConfig[] = [];
    const trustBoundaryParticipants = new Map<string, Set<string>>();

    for (const participant of participants) {
        const label = participant.title?.trim() || participant.ID;
        const targetParticipant = participant.collapseTo ? participantById.get(participant.collapseTo) : undefined;
        const displayLabel = targetParticipant?.title?.trim() || targetParticipant?.ID || label;
        const domains = Array.isArray(participant.domains)
            ? participant.domains.filter((domain): domain is string => typeof domain === 'string' && domain.trim().length > 0)
            : [];

        if (participant.inScope !== false) {
            participantFilter.push(...domains);
        }

        if (domains.length > 0) {
            collapseParticipants.push({
                name: displayLabel,
                participants: domains,
            });
        }

        if (!participant.collapseTo && participant.properties && Object.keys(participant.properties).length > 0) {
            participantProperties.push({
                participants: [label],
                properties: participant.properties,
            });
        }

        if (participant.trustBoundary) {
            const existing = trustBoundaryParticipants.get(participant.trustBoundary) ?? new Set<string>();
            existing.add(label);
            for (const domain of domains) {
                existing.add(domain);
            }
            trustBoundaryParticipants.set(participant.trustBoundary, existing);
        }
    }

    const trustBoundaries: TrustBoundaryConfig[] = Array.from(trustBoundaryCatalog.values()).map(boundary => ({
        name: boundary.title?.trim() || boundary.ID,
        color: boundary.color,
        participants: Array.from(trustBoundaryParticipants.get(boundary.ID) ?? []),
    })).filter(boundary => boundary.participants.length > 0);

    return {
        browserParticipant: typeof rawConfig.browserParticipant === 'string' ? rawConfig.browserParticipant : undefined,
        participantFilter: Array.from(new Set(participantFilter)),
        excludePaths: Array.isArray(rawConfig.excludePaths)
            ? rawConfig.excludePaths.filter((item): item is string => typeof item === 'string')
            : [],
        messagePrefixes: rawConfig.messagePrefixes && typeof rawConfig.messagePrefixes === 'object'
            ? rawConfig.messagePrefixes as Record<string, string>
            : {},
        trustBoundaries,
        collapseParticipants,
        participantProperties,
    };
}

export function load_indexHAR_file(indexPath: string): HarIndexFile {
    const fullPath = path.resolve(indexPath);
    if (!fs.existsSync(fullPath)) {
        throw new Error(`indexHAR file not found: ${fullPath}`);
    }

    const raw = fs.readFileSync(fullPath, 'utf8');
    const parsed = yaml.load(raw);

    if (!parsed || typeof parsed !== 'object') {
        throw new Error(`Invalid indexHAR format in ${fullPath}`);
    }

    const onDisk = parsed as IndexHARv2OnDisk;
    if (onDisk.schemaVersion !== 'indexHAR.v2' || !Array.isArray(onDisk.entries)) {
        throw new Error(`Invalid indexHAR format in ${fullPath}`);
    }

    // Map column name -> position so the loader tolerates column reordering/extension.
    const col = new Map(onDisk.columns.map((name, i) => [name, i]));
    const get = <T>(row: IndexV2Row, name: string): T => row[col.get(name) as number] as T;

    const entries: HarIndexEntry[] = onDisk.entries.map((row, index) => ({
        requestId: index + 1, // implicit: chronological order
        method: get<string>(row, 'method'),
        url: get<string>(row, 'url'),
        status: get<number>(row, 'status'),
        entryOffset: get<number>(row, 'offset'),
        entryLength: get<number>(row, 'length'),
    }));

    return {
        schemaVersion: 'indexHAR.v2',
        harFile: onDisk.harFile,
        harBytes: onDisk.harBytes,
        harSha256: onDisk.harSha256,
        totalRequests: onDisk.totalRequests,
        entries,
    };
}

function getRegistrableDomain(host: string): string {
    const parts = host.split('.').filter(Boolean);
    if (parts.length <= 2) {
        return host;
    }

    const lastTwo = parts.slice(-2).join('.');
    if (MULTI_PART_SUFFIXES.has(lastTwo) && parts.length >= 3) {
        return parts.slice(-3).join('.');
    }

    return lastTwo;
}

function toWildcardPattern(host: string): string {
    return `*.${getRegistrableDomain(host)}`;
}

function indexEntryHost(entry: HarIndexEntry): string | undefined {
    return parseUrl(entry.url || '')?.host;
}

function summarizeHosts(indexData: HarIndexFile): HostCountSummary[] {
    const counts = new Map<string, number>();

    for (const entry of indexData.entries) {
        const host = indexEntryHost(entry);
        if (!host) {
            continue;
        }
        counts.set(host, (counts.get(host) || 0) + 1);
    }

    return Array.from(counts.entries())
        .map(([host, requestCount]) => ({ host, requestCount }))
        .sort((a, b) => b.requestCount - a.requestCount || a.host.localeCompare(b.host));
}

function findClusterMatches(hosts: string[]): KnownParticipantCluster[] {
    return KNOWN_PARTICIPANT_CLUSTERS.filter(cluster =>
        hosts.some(host => cluster.patterns.some(pattern => matchesBoundaryRule(host, pattern)))
    );
}

function sanitizeParticipantId(value: string): string {
    return value
        .toUpperCase()
        .replace(/[^A-Z0-9]+/g, '_')
        .replace(/^_+|_+$/g, '')
        .replace(/_+/g, '_') || 'PARTICIPANT';
}

function createGenericParticipantProperties(): Record<string, ParticipantPropertyValue> {
    return {
        authentication: 'TODO',
        authorization: 'TODO',
        dataSensitivity: 'TODO',
        notes: ['refine with LLM after inspecting .indexHAR.yaml'],
    };
}

function createThirdPartyProperties(): Record<string, ParticipantPropertyValue> {
    return {
        authentication: 'unknown / vendor-specific',
        authorization: 'vendor-managed',
        dataSensitivity: 'mixed external processing',
        notes: ['extract important vendors from collapsed source groups into their own visible participants over time'],
    };
}

function toTitleFromId(value: string): string {
    return value.toLowerCase().split('_').filter(Boolean).map(part => part[0]?.toUpperCase() + part.slice(1)).join(' ');
}

function buildStarterConfigObject(indexData: HarIndexFile, options: StarterConfigOptions = {}): StarterHar2SeqConfig {
    const hostsInOrder = indexData.entries
        .map(entry => indexEntryHost(entry))
        .filter((host): host is string => Boolean(host));
    const firstHost = hostsInOrder[0];
    const allHosts = Array.from(new Set(hostsInOrder));
    const firstPartyPatterns = options.firstPartyPatterns && options.firstPartyPatterns.length > 0
        ? options.firstPartyPatterns
        : [firstHost ? toWildcardPattern(firstHost) : '*.example.com'];
    const firstPartyHosts = allHosts.filter(host => firstPartyPatterns.some(pattern => matchesBoundaryRule(host, pattern)));
    const thirdPartyHosts = allHosts.filter(host => !firstPartyHosts.includes(host));
    const clusterMatches = findClusterMatches(thirdPartyHosts);
    const matchedHosts = new Set<string>();
    const participants: ParticipantConfig[] = [];

    for (const host of firstPartyHosts) {
        participants.push({
            ID: sanitizeParticipantId(host),
            title: host,
            domains: [host],
            trustBoundary: 'FIRST_PARTY',
            inScope: true,
            properties: createGenericParticipantProperties(),
        });
    }

    if (options.collapseThirdParty) {
        participants.push({
            ID: 'THIRD_PARTY',
            title: '3rd Party',
            domains: [],
            trustBoundary: 'THIRD_PARTY',
            inScope: true,
            properties: createThirdPartyProperties(),
        });
    }

    for (const cluster of clusterMatches) {
        const clusterHosts = thirdPartyHosts.filter(host => cluster.patterns.some(pattern => matchesBoundaryRule(host, pattern)));
        if (clusterHosts.length === 0) {
            continue;
        }

        clusterHosts.forEach(host => matchedHosts.add(host));
        participants.push({
            ID: cluster.id,
            title: cluster.name,
            domains: clusterHosts,
            trustBoundary: 'THIRD_PARTY',
            inScope: true,
            properties: cluster.properties || createGenericParticipantProperties(),
        });
    }

    const remainingHosts = thirdPartyHosts.filter(host => !matchedHosts.has(host));
    const remainingByRegistrableDomain = new Map<string, string[]>();
    for (const host of remainingHosts) {
        const key = getRegistrableDomain(host);
        const existing = remainingByRegistrableDomain.get(key) ?? [];
        existing.push(host);
        remainingByRegistrableDomain.set(key, existing);
    }

    for (const [domain, hosts] of remainingByRegistrableDomain.entries()) {
        const id = sanitizeParticipantId(domain);
        participants.push({
            ID: id,
            title: options.collapseThirdParty ? toTitleFromId(id) : domain,
            domains: hosts,
            trustBoundary: 'THIRD_PARTY',
            collapseTo: options.collapseThirdParty ? 'THIRD_PARTY' : undefined,
            inScope: true,
            properties: createGenericParticipantProperties(),
        });
    }

    return {
        browserParticipant: 'Browser',
        excludePaths: [],
        messagePrefixes: {
            GET: 'REQ ',
            POST: 'AUTH ',
            PUT: 'PUT ',
            PATCH: 'PATCH ',
            DELETE: 'DEL ',
        },
        trustBoundaries: [
            {
                ID: 'FIRST_PARTY',
                title: 'First-Party Boundary',
                color: '#D7F3E3',
            },
            {
                ID: 'THIRD_PARTY',
                title: 'Third-Party Boundary',
                color: '#F5F5F5',
            },
        ],
        participants,
    };
}

export function generate_starter_HAR_config_yaml(
    harPath: string,
    indexPath?: string,
    options: StarterConfigOptions = {}
): string {
    const indexData = indexPath ? load_indexHAR_file(indexPath) : generate_indexHAR(harPath);
    const hostSummary = summarizeHosts(indexData);
    const configObject = buildStarterConfigObject(indexData, options);
    const maxTopHosts = options.maxTopHosts ?? 12;
    const commentLines = [
        '# HAR_2_TM_tool starter config',
        `# HAR file: ${options.outputHarPath || path.resolve(harPath)}`,
        '# Generated from HAR/.indexHAR.yaml. Refine with an LLM or by hand.',
        '# participants: the primary editing surface. Move domains between participants, trust boundaries, and collapse targets over time.',
        '# Diagram/view granularity is a tool option, not part of the semantic config.',
        '#',
        '# Top discovered hosts by request count:',
        ...hostSummary.slice(0, maxTopHosts).map(item => `# - ${item.host}: ${item.requestCount}`),
        '',
    ];

    const yamlBody = yaml.dump(configObject, {
        lineWidth: -1,
        noRefs: true,
        sortKeys: false,
    });

    return `${commentLines.join('\n')}${yamlBody}`;
}

export function create_starter_HAR_config_file(
    harPath: string,
    outputPath: string,
    indexPath?: string,
    options: StarterConfigOptions = {}
): string {
    const outPath = path.resolve(outputPath);
    const yamlText = generate_starter_HAR_config_yaml(harPath, indexPath, options);
    fs.mkdirSync(path.dirname(outPath), { recursive: true });
    fs.writeFileSync(outPath, yamlText.endsWith('\n') ? yamlText : `${yamlText}\n`, 'utf8');
    return outPath;
}

function collectEvents(har: HarFile, config: Har2SeqConfig, options: Har2SeqOptions = {}): SequenceEvent[] {
    const participants = getParticipantFilter(config);
    const excludePaths = config.excludePaths ?? [];
    const collapseRules = getCollapseRules(config);
    const renderingConfig = resolveRenderingConfig(options);
    const singleCallPerSourceHost = renderingConfig.singleCallPerSourceHost ?? false;
    const singleCallPerParticipant = renderingConfig.singleCallPerParticipant ?? false;
    const entries = normalizeEntries(har.log.entries);

    const events: SequenceEvent[] = [];

    for (const entry of entries) {
        const parsedUrl = parseUrl(entry.request?.url);
        if (!parsedUrl) {
            continue;
        }

        const { host, path: requestPath } = parsedUrl;
        if (!host) {
            continue;
        }

        const pathName = requestPath.split('?')[0] || '/';

        if (!isParticipantAllowed(host, participants)) {
            continue;
        }

        if (isExcluded(host, pathName, excludePaths)) {
            continue;
        }

        events.push({
            host: collapseParticipantHost(host, collapseRules),
            boundaryHost: host,
            path: requestPath,
            method: (entry.request?.method || 'GET').toUpperCase(),
            status: Number(entry.response?.status ?? 0),
            startedDateTime: entry.startedDateTime,
        });
    }

    if (singleCallPerSourceHost) {
        const firstEventBySourceHost = new Map<string, SequenceEvent>();

        for (const event of events) {
            if (!firstEventBySourceHost.has(event.boundaryHost)) {
                firstEventBySourceHost.set(event.boundaryHost, event);
            }
        }

        return Array.from(firstEventBySourceHost.values());
    }

    if (singleCallPerParticipant) {
        const firstEventByHost = new Map<string, SequenceEvent>();

        for (const event of events) {
            if (!firstEventByHost.has(event.host)) {
                firstEventByHost.set(event.host, event);
            }
        }

        return Array.from(firstEventByHost.values());
    }

    return events;
}

function resolveBoundaryName(host: string, boundaries: TrustBoundaryConfig[], sourceHost?: string): string {
    for (const boundary of boundaries) {
        if (!boundary.participants || boundary.participants.length === 0) {
            continue;
        }

        if (boundary.participants.some(rule => matchesBoundaryRule(host, rule))) {
            return boundary.name;
        }

        if (sourceHost && boundary.participants.some(rule => matchesBoundaryRule(sourceHost, rule))) {
            return boundary.name;
        }
    }

    return 'External Boundary';
}

function boundaryColor(boundaryName: string, boundaries: TrustBoundaryConfig[]): string {
    const found = boundaries.find(boundary => boundary.name === boundaryName);
    return found?.color || '#EAEAEA';
}

function buildHostInventory(har: HarFile, config: Har2SeqConfig): Map<string, string[]> {
    const participants = getParticipantFilter(config);
    const excludePaths = config.excludePaths ?? [];
    const collapseRules = getCollapseRules(config);
    const entries = normalizeEntries(har.log.entries);
    const hostInventory = new Map<string, Set<string>>();

    for (const entry of entries) {
        const parsedUrl = parseUrl(entry.request?.url);
        if (!parsedUrl) {
            continue;
        }

        const { host, path: requestPath } = parsedUrl;
        if (!host) {
            continue;
        }

        const pathName = requestPath.split('?')[0] || '/';
        if (!isParticipantAllowed(host, participants) || isExcluded(host, pathName, excludePaths)) {
            continue;
        }

        const displayHost = collapseParticipantHost(host, collapseRules);
        const hosts = hostInventory.get(displayHost) ?? new Set<string>();
        hosts.add(host);
        hostInventory.set(displayHost, hosts);
    }

    return new Map(Array.from(hostInventory.entries()).map(([displayHost, hosts]) => [displayHost, Array.from(hosts).sort()]));
}

export function generateMermaidFromHar(
    har: HarFile,
    config: Har2SeqConfig = {},
    options: Har2SeqOptions = {}
): string {
    const browserParticipant = options.browserParticipant ?? config.browserParticipant ?? 'Browser';
    const includeActivation = options.includeActivation ?? true;
    const messagePrefixes = config.messagePrefixes ?? {};
    const propertyRules = config.participantProperties ?? [];
    const renderingConfig = resolveRenderingConfig(options);
    const includeSourceHostInLabel = renderingConfig.includeSourceHostInLabel ?? false;

    const events = collectEvents(har, config, options);
    const hosts = Array.from(new Set(events.map(event => event.host)));
    const aliasMap = new Map<string, string>();
    hosts.forEach((host, index) => aliasMap.set(host, toParticipantAlias(index)));
    const sourceHostByDisplayHost = new Map<string, string>();
    for (const event of events) {
        if (!sourceHostByDisplayHost.has(event.host)) {
            sourceHostByDisplayHost.set(event.host, event.boundaryHost);
        }
    }

    const lines: string[] = ['sequenceDiagram', `    participant ${browserParticipant}`];

    for (const host of hosts) {
        const alias = aliasMap.get(host)!;
        lines.push(`    participant "${escapeMermaidLabel(host)}" as ${alias}`);
        lines.push(...renderMermaidParticipantNote(
            alias,
            resolveParticipantProperties(host, sourceHostByDisplayHost.get(host) || host, propertyRules)
        ));
    }

    for (const event of events) {
        const alias = aliasMap.get(event.host);
        if (!alias) {
            continue;
        }

        const prefix = messagePrefixes[event.method] ?? '';
        lines.push(`    ${browserParticipant}->>${alias}: ${buildRequestLabel(prefix, event.method, event.path, event.host, event.boundaryHost, includeSourceHostInLabel)}`);
        if (includeActivation) {
            lines.push(`    activate ${alias}`);
        }
        lines.push(`    ${alias}-->>${browserParticipant}: ${event.status}`);
        if (includeActivation) {
            lines.push(`    deactivate ${alias}`);
        }
    }

    return `${lines.join('\n')}\n`;
}

export function generatePlantUmlFromHar(
    har: HarFile,
    config: Har2SeqConfig = {},
    options: Har2SeqOptions = {}
): string {
    const renderingConfig = resolveRenderingConfig(options);
    const highLevelDfd = renderingConfig.view === 'HighLevelDFD';
    const browserParticipant = options.browserParticipant ?? config.browserParticipant ?? 'Browser';
    const messagePrefixes = config.messagePrefixes ?? {};
    const trustBoundaries = config.trustBoundaries ?? [];
    const propertyRules = config.participantProperties ?? [];
    const includeSourceHostInLabel = highLevelDfd
        ? false
        : (renderingConfig.includeSourceHostInLabel ?? false);

    const events = collectEvents(har, config, options);
    const hostInventory = buildHostInventory(har, config);
    const hosts = Array.from(new Set(events.map(event => event.host)));
    const aliasMap = new Map<string, string>();
    hosts.forEach((host, index) => aliasMap.set(host, toParticipantAlias(index)));

    const boundaryNames: string[] = [];
    const hostByBoundary = new Map<string, string[]>();

    const sourceHostByDisplayHost = new Map<string, string>();
    for (const event of events) {
        if (!sourceHostByDisplayHost.has(event.host)) {
            sourceHostByDisplayHost.set(event.host, event.boundaryHost);
        }
    }

    for (const host of hosts) {
        const assignedBoundary = resolveBoundaryName(host, trustBoundaries, sourceHostByDisplayHost.get(host));
        if (!hostByBoundary.has(assignedBoundary)) {
            hostByBoundary.set(assignedBoundary, []);
            boundaryNames.push(assignedBoundary);
        }
        hostByBoundary.get(assignedBoundary)!.push(host);
    }

    const lines: string[] = [
        '@startuml',
        'hide footbox',
        `actor "${escapePlantUmlLabel(browserParticipant)}" as BROWSER`,
    ];
    const participantNotesByAlias = new Map<string, string[]>();

    for (const boundaryName of boundaryNames) {
        const boundaryHosts = hostByBoundary.get(boundaryName) ?? [];
        if (boundaryHosts.length === 0) {
            continue;
        }

        lines.push(`box "${escapePlantUmlLabel(boundaryName)}" ${boundaryColor(boundaryName, trustBoundaries)}`);
        for (const host of boundaryHosts) {
            const alias = aliasMap.get(host)!;
            lines.push(`  participant "${escapePlantUmlLabel(host)}" as ${alias}`);
        }
        lines.push('end box');
        for (const host of boundaryHosts) {
            const alias = aliasMap.get(host)!;
            const noteLines = renderPlantUmlParticipantNote(
                alias,
                resolveParticipantProperties(host, sourceHostByDisplayHost.get(host) || host, propertyRules),
                {
                    backgroundColor: highLevelDfd ? '#E0E0E0' : undefined,
                    hiddenHosts: highLevelDfd ? (hostInventory.get(host) || []) : undefined,
                    hiddenHostsLabel: highLevelDfd ? `${host} hosts` : undefined,
                    overParticipant: highLevelDfd,
                }
            );

            // Keep notes adjacent to calls instead of grouping all notes under participant
            // declarations so each participant context appears right before first interaction.
            participantNotesByAlias.set(alias, noteLines);
        }
    }

    const notedAliases = new Set<string>();
    for (const event of events) {
        const alias = aliasMap.get(event.host);
        if (!alias) {
            continue;
        }

        if (!notedAliases.has(alias)) {
            lines.push(...(participantNotesByAlias.get(alias) ?? []));
            notedAliases.add(alias);
        }

        const prefix = messagePrefixes[event.method] ?? '';
        const requestLabel = highLevelDfd
            ? buildHighLevelCallLabel(event.host, renderingConfig.genericCallDescription)
            : buildRequestLabel(prefix, event.method, event.path, event.host, event.boundaryHost, includeSourceHostInLabel);
        lines.push(`BROWSER -> ${alias}: ${requestLabel}`);
    }

    lines.push('@enduml');
    return `${lines.join('\n')}\n`;
}

export function generateSequenceFromHar(
    har: HarFile,
    config: Har2SeqConfig = {},
    options: Har2SeqOptions = {}
): string {
    const format = options.format ?? 'plantuml';

    if (format === 'mermaid') {
        return generateMermaidFromHar(har, config, options);
    }

    return generatePlantUmlFromHar(har, config, options);
}

export function buildMermaidFromHarFile(
    harPath: string,
    configPath?: string,
    options: Har2SeqOptions = {}
): string {
    const har = loadHarFile(harPath);
    const config = configPath ? loadHar2SeqConfig(configPath) : {};
    return generateMermaidFromHar(har, config, options);
}

export function buildSequenceFromHarFile(
    harPath: string,
    configPath?: string,
    options: Har2SeqOptions = {}
): string {
    const har = loadHarFile(harPath);
    const config = configPath ? loadHar2SeqConfig(configPath) : {};
    return generateSequenceFromHar(har, config, options);
}

export function buildPlantUmlFromHarFile(
    harPath: string,
    configPath?: string,
    options: Har2SeqOptions = {}
): string {
    const har = loadHarFile(harPath);
    const config = configPath ? loadHar2SeqConfig(configPath) : {};
    return generatePlantUmlFromHar(har, config, options);
}

export interface HarEntryByteRange {
    offset: number;
    length: number;
}

/**
 * Single-pass byte scanner over a raw HAR buffer that returns the byte range of every object
 * inside `log.entries`, in file order. It never builds a parsed object graph for the whole file,
 * so it scales to very large HARs (hundreds of MB): memory stays O(number of entries), not O(file).
 * Each returned range is a self-contained JSON object that can be `JSON.parse`d on its own.
 */
export function indexHarEntryByteRanges(buffer: Buffer): HarEntryByteRange[] {
    const keyNeedle = Buffer.from('"entries"');
    const keyPos = buffer.indexOf(keyNeedle);
    if (keyPos === -1) {
        throw new Error('Invalid HAR: missing "entries" array');
    }

    // Advance to the array's opening '[' (skipping the ':' and any whitespace after the key).
    let start = keyPos + keyNeedle.length;
    while (start < buffer.length && buffer[start] !== 0x5b /* [ */) {
        start++;
    }
    if (start >= buffer.length) {
        throw new Error('Invalid HAR: "entries" array opening bracket not found');
    }

    const ranges: HarEntryByteRange[] = [];
    let arrayDepth = 0; // bracket depth ('['); entries array itself is depth 1
    let objectDepth = 0; // brace depth ('{') inside the current array element
    let inString = false;
    let escaped = false;
    let entryStart = -1;

    for (let p = start; p < buffer.length; p++) {
        const c = buffer[p];

        if (inString) {
            if (escaped) {
                escaped = false;
            } else if (c === 0x5c /* \ */) {
                escaped = true;
            } else if (c === 0x22 /* " */) {
                inString = false;
            }
            continue;
        }

        switch (c) {
            case 0x22 /* " */:
                inString = true;
                break;
            case 0x5b /* [ */:
                arrayDepth++;
                break;
            case 0x5d /* ] */:
                arrayDepth--;
                if (arrayDepth === 0) {
                    return ranges; // closed the entries array
                }
                break;
            case 0x7b /* { */:
                if (objectDepth === 0 && arrayDepth === 1) {
                    entryStart = p; // start of a top-level entry object
                }
                objectDepth++;
                break;
            case 0x7d /* } */:
                objectDepth--;
                if (objectDepth === 0 && arrayDepth === 1 && entryStart !== -1) {
                    ranges.push({ offset: entryStart, length: p - entryStart + 1 });
                    entryStart = -1;
                }
                break;
            default:
                break;
        }
    }

    return ranges;
}

/**
 * Read a single HAR entry directly from the source .har using a byte offset/length from the index.
 * This is an O(1) seek + bounded read (no sequential scan, no whole-file parse), so it stays fast
 * regardless of HAR size. Pair with the entryOffset/entryLength on a HarIndexEntry.
 */
export function read_har_entry(harPath: string, entryOffset: number, entryLength: number): HarEntry {
    const fd = fs.openSync(path.resolve(harPath), 'r');
    try {
        const buffer = Buffer.allocUnsafe(entryLength);
        fs.readSync(fd, buffer, 0, entryLength, entryOffset);
        return JSON.parse(buffer.toString('utf8')) as HarEntry;
    } finally {
        fs.closeSync(fd);
    }
}

export function generate_indexHAR(harPath: string): HarIndexFile {
    const absHarPath = path.resolve(harPath);
    const buffer = fs.readFileSync(absHarPath);
    const ranges = indexHarEntryByteRanges(buffer);

    // Parse each entry slice individually (bounded memory) to read its index metadata; the full
    // body stays on disk and is fetched on demand via read_har_entry(entryOffset, entryLength).
    const parsed = ranges.map(range => {
        const slice = buffer.toString('utf8', range.offset, range.offset + range.length);
        const entry = JSON.parse(slice) as HarEntry;
        return { range, entry };
    });

    // requestId N === the Nth entry in chronological order (same ordering as the sequence views).
    parsed.sort((a, b) => {
        const at = a.entry.startedDateTime;
        const bt = b.entry.startedDateTime;
        if (!at && !bt) return 0;
        if (!at) return 1;
        if (!bt) return -1;
        const av = Date.parse(at);
        const bv = Date.parse(bt);
        if (Number.isNaN(av) || Number.isNaN(bv)) return 0;
        return av - bv;
    });

    const indexedEntries: HarIndexEntry[] = parsed.map(({ range, entry }, index) => ({
        requestId: index + 1,
        method: (entry.request?.method || 'GET').toUpperCase(),
        url: entry.request?.url || '',
        status: Number(entry.response?.status ?? 0),
        entryOffset: range.offset,
        entryLength: range.length,
    }));

    return {
        schemaVersion: 'indexHAR.v2',
        harFile: path.basename(absHarPath),
        harBytes: buffer.length,
        harSha256: crypto.createHash('sha256').update(buffer).digest('hex'),
        totalRequests: indexedEntries.length,
        entries: indexedEntries,
    };
}

export function create_indexHAR_file(harPath: string, outputPath?: string): string {
    const absHarPath = path.resolve(harPath);
    const outPath = outputPath
        ? path.resolve(outputPath)
        : path.join(path.dirname(absHarPath), `${path.parse(absHarPath).name}.indexHAR.yaml`);

    const indexData = generate_indexHAR(absHarPath);
    fs.mkdirSync(path.dirname(outPath), { recursive: true });

    const onDisk: IndexHARv2OnDisk = {
        schemaVersion: 'indexHAR.v2',
        harFile: indexData.harFile,
        harBytes: indexData.harBytes,
        harSha256: indexData.harSha256,
        totalRequests: indexData.totalRequests,
        columns: [...INDEX_V2_COLUMNS],
        // requestId is implicit (row index + 1); keys live once in `columns`, not on every row.
        entries: indexData.entries.map((e): IndexV2Row => [e.method, e.url, e.status, e.entryOffset, e.entryLength]),
    };

    const yamlText = yaml.dump(onDisk, {
        lineWidth: -1,
        noRefs: true,
        sortKeys: false,
        flowLevel: 2, // render each entry row as an inline [..] array
    });
    fs.writeFileSync(outPath, yamlText.endsWith('\n') ? yamlText : `${yamlText}\n`, 'utf8');

    return outPath;
}

export function generate_puml_sequence(
    harPath: string,
    configPath?: string,
    options: Omit<Har2SeqOptions, 'format'> = {}
): string {
    const har = loadHarFile(harPath);
    const config = configPath ? loadHar2SeqConfig(configPath) : {};

    return generatePlantUmlFromHar(har, config, {
        ...options,
        format: 'plantuml',
    });
}
