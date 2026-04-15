#!/usr/bin/env node
/**
 * CLI to create / review Jira tickets for unmitigated threats.
 *
 * Port of the Python `create_jira_tickets.py` script.
 *
 * Usage:
 *   tsx src/scripts/create-jira-tickets.ts \
 *     --rootTMYaml path/to/ThreatModel.yaml \
 *     --dest PROJECT_KEY \
 *     [--type "Risk"]          # Jira issue type (default: "Security Bug")
 *     [--TMID SubModelId]      # process only a specific child TM
 *     [--list]                 # list-only mode
 *     [--dryRun]               # show ticket details without calling Jira
 *     [--csv path/out.csv]     # export Jira-importable CSV file
 *     [--format wiki|markdown] # description format (default: markdown for CSV, wiki for interactive)
 *     [--epic EPIC-123]        # parent Epic key for all created issues
 *     [--tmUri https://…]      # base URL for threat-model links
 *     [--field KEY=VALUE …]    # additional Jira fields
 *     [--jira URL]             # or ATLASSIAN_URI env
 *     [--username USER]        # or ATLASSIAN_USERNAME env
 *     [--password TOKEN]       # or ATLASSIAN_PASSWORD env
 */

import { createInterface } from 'readline';
import { exec } from 'child_process';
import fs from 'fs';
import path from 'path';
import yaml from 'js-yaml';

import ThreatModel from '../models/ThreatModel.js';
import type Threat from '../models/Threat.js';
import { parseFlag, parseOption, parseMultiOption } from './cli-options.js';
import {
    JiraClient,
    buildRiskReviewUrl,
    riskDescription,
    riskDescriptionFormatted,
    csvDescriptionMarkdown,
    mapCvssToImpact,
    mapCvssToPriority,
    riskRating,
    treatmentPlanDate,
    formatJiraDate,
    type DescriptionFormat,
} from '../jira/index.js';

// ── Argument parsing ────────────────────────────────────────────────────────

interface CliArgs {
    rootTMYaml: string;
    tmId?: string;
    list: boolean;
    dryRun: boolean;
    csvOut?: string;
    format: DescriptionFormat;
    epic?: string;
    jira: string;
    username: string;
    password: string;
    dest: string;
    issueType: string;
    tmUri: string;
    linkPrefix?: string;
    extraFields: Record<string, string>;
}

function parseArgs(argv: string[]): CliArgs {
    const rootTMYaml = parseOption(argv, 'rootTMYaml');
    if (!rootTMYaml) { console.error('--rootTMYaml is required'); process.exit(1); }
    if (!fs.existsSync(rootTMYaml)) { console.error(`File not found: ${rootTMYaml}`); process.exit(1); }

    const dest = parseOption(argv, 'dest');
    if (!dest) { console.error('--dest (Jira project key) is required'); process.exit(1); }

    const isDryRun = parseFlag(argv, 'dryRun');
    const csvOut = parseOption(argv, 'csv');
    const isList = parseFlag(argv, 'list');
    const isOffline = isDryRun || !!csvOut || isList;

    const jira = parseOption(argv, 'jira') ?? process.env.ATLASSIAN_URI ?? (isOffline ? 'https://dry-run.atlassian.net' : '');
    if (!jira) { console.error('Please specify --jira or ATLASSIAN_URI environment'); process.exit(1); }

    const username = parseOption(argv, 'username') ?? process.env.ATLASSIAN_USERNAME ?? (isOffline ? 'dry-run' : '');
    if (!username) { console.error('Please specify --username or ATLASSIAN_USERNAME environment'); process.exit(1); }

    const password = parseOption(argv, 'password') ?? process.env.ATLASSIAN_PASSWORD ?? (isOffline ? 'dry-run' : '');
    if (!password) { console.error('Please specify --password or ATLASSIAN_PASSWORD environment'); process.exit(1); }

    // Parse --field KEY=VALUE pairs
    const rawFields = parseMultiOption(argv, 'field');
    const extraFields: Record<string, string> = {};
    for (const f of rawFields) {
        const eq = f.indexOf('=');
        if (eq > 0) {
            extraFields[f.slice(0, eq)] = f.slice(eq + 1);
        }
    }

    return {
        rootTMYaml,
        tmId:       parseOption(argv, 'TMID'),
        list:       isList,
        dryRun:     isDryRun,
        csvOut,
        format:     (parseOption(argv, 'format') as DescriptionFormat) ?? (csvOut ? 'markdown' : 'wiki'),
        epic:       parseOption(argv, 'epic') ?? 'PROT-303',
        jira,
        username,
        password,
        dest,
        issueType:  parseOption(argv, 'type') ?? 'Security Bug',
        tmUri:      parseOption(argv, 'tmUri') ?? process.env.R3TM_HOME ?? 'https://example.com',
        linkPrefix: parseOption(argv, 'linkPrefix'),
        extraFields,
    };
}

// ── Interactive helpers ─────────────────────────────────────────────────────

function ask(prompt: string): Promise<string> {
    const rl = createInterface({ input: process.stdin, output: process.stdout });
    return new Promise(resolve => {
        rl.question(prompt, answer => { rl.close(); resolve(answer.trim()); });
    });
}

function openUrl(url: string): void {
    const cmd = process.platform === 'darwin'
        ? 'open'
        : process.platform === 'win32'
          ? 'start'
          : 'xdg-open';
    exec(`${cmd} "${url}"`);
}

// ── YAML ticket-link updater ────────────────────────────────────────────────

function updateThreatWithRef(threat: Threat, ticketRef: string): boolean {
    const tm = threat.threatModel as ThreatModel;
    const originDict = tm.originDict;
    if (!originDict?.threats) return false;

    const ythreat = (originDict.threats as Record<string, unknown>[]).find(
        (t: Record<string, unknown>) => t.ID === threat.id || t.ID === (threat as any)._id,
    );
    if (!ythreat) {
        console.error(`Unable to find threat ${threat.id} in ${tm.fileName}`);
        return false;
    }
    ythreat.ticketLink = ticketRef;

    // Re-serialise to the original file
    console.log('Updating:', tm.fileName);
    fs.writeFileSync(tm.fileName, yaml.dump(originDict, { lineWidth: -1, noRefs: true }), 'utf8');
    return true;
}

// ── CSV export ──────────────────────────────────────────────────────────────

/** Escape a value for CSV: wrap in double-quotes, doubling any internal quotes. */
function csvCell(value: string): string {
    return `"${value.replace(/"/g, '""')}"`;
}

function exportCsv(
    threats: Threat[],
    args: CliArgs,
): string {
    // Standard Jira CSV-import columns
    const headers = [
        'Create Ticket',
        'Section',
        'Summary',
        'Issue Type',
        'Priority',
        'Project Key',
        'Description',
        'Labels',
        'Epic Link',
        'CVSS Score',
        'CVSS Vector',
        'Severity',
        'Impact',
        ...(args.linkPrefix ? [] : ['Impact Description']),
        'Risk Type',
        'Likelihood',
        'Risk Rating',
        'Due Date',
        'Threat ID',
        'Ticket Link',
        ...Object.keys(args.extraFields),
    ];

    const rows: string[] = [headers.map(csvCell).join(',')];

    for (const threat of threats) {
        if (args.tmId && (threat.threatModel as any)._id !== args.tmId) continue;

        const hasTicket = !!threat.ticketLink;

        const cvss   = threat.cvssObject;
        const severity = cvss ? cvss.getSmartScoreSeverity() : 'N/A';
        const score  = threat.getSmartScoreVal();
        const vector = cvss ? cvss.clean_vector() : '';
        const rr     = riskRating(threat.getSmartScoreDesc(), 3);
        const tmId   = (threat.threatModel as any)._id ?? '';
        const section = (threat.threatModel as any).getHierarchicalId?.() ?? tmId;

        const labels = tmId || '';

        const cells = [
            hasTicket ? 'No' : 'Yes',
            section,
            `Remediation for: ${threat.title}`,  // threat ID: ${threat.id}
            args.issueType,
            mapCvssToPriority(severity),
            args.dest,
            args.linkPrefix
                ? csvDescriptionMarkdown(threat, args.linkPrefix)
                : riskDescriptionFormatted(threat, args.format, args.tmUri),
            labels,
            args.epic ?? '',
            String(score),
            vector,
            severity,
            mapCvssToImpact(severity),
            ...(args.linkPrefix ? [] : [threat.impact_desc]),
            'Security Risk',
            '3 - Possible',
            String(rr),
            formatJiraDate(treatmentPlanDate(rr)),
            threat.id,
            threat.ticketLink ?? '',
            ...Object.values(args.extraFields),
        ];

        rows.push(cells.map(csvCell).join(','));
    }

    return rows.join('\n') + '\n';
}

// ── Main ────────────────────────────────────────────────────────────────────

async function main() {
    const args = parseArgs(process.argv.slice(2));

    const rootTM = new ThreatModel(path.resolve(args.rootTMYaml));
    // const unmitigated = rootTM.getThreatsByFullyMitigatedAndOperational(false, false);
    const unmitigated = rootTM.getThreatsByFullyMitigated(false);
    // ── CSV export mode ─────────────────────────────────────────────────────
    if (args.csvOut) {
        const csv = exportCsv(unmitigated, args);
        const outPath = path.resolve(args.csvOut);
        fs.mkdirSync(path.dirname(outPath), { recursive: true });
        fs.writeFileSync(outPath, '\uFEFF' + csv, 'utf8');
        console.log(`CSV written to ${outPath} (${unmitigated.length} threats)`);
        return;
    }

    const client = new JiraClient({
        baseUrl: args.jira,
        username: args.username,
        token: args.password,
    });

    for (let idx = 0; idx < unmitigated.length; idx++) {
        const threat = unmitigated[idx];
        const tm = threat.threatModel as ThreatModel;

        console.log('-'.repeat(80));
        console.log(`Threat [${idx + 1}/${unmitigated.length}] (${threat.id})`);

        // Filter by sub-model ID if requested
        if (args.tmId && (tm as any)._id !== args.tmId) {
            console.log('   (Skipping)');
            continue;
        }

        const existingLink = threat.ticketLink;
        let ref = '   not linked  ';
        if (existingLink) {
            ref = existingLink.split('/').pop() ?? existingLink;
            if (!args.list) {
                console.log('   (Skipping – already linked)');
                continue;
            }
        }

        console.log(`[${ref.padStart(16)}] : ${threat.title}`);

        if (args.list) continue;

        if (args.dryRun) {
            const cvss = threat.cvssObject;
            const severity = cvss ? cvss.getSmartScoreSeverity() : 'N/A';
            const score = threat.getSmartScoreVal();
            const rr = riskRating(threat.getSmartScoreDesc(), 3);
            console.log(`  Project:     ${args.dest}`);
            console.log(`  Issue Type:  ${args.issueType}`);
            console.log(`  Summary:     Remediation for: ${threat.title}  // ${threat.id}`);
            console.log(`  CVSS Score:  ${score} (${severity})`);
            console.log(`  Impact:      ${mapCvssToImpact(severity)}`);
            console.log(`  Risk Rating: ${rr}`);
            console.log(`  Target Date: ${formatJiraDate(treatmentPlanDate(rr))}`);
            console.log(`  Threat Model: ${(tm as any)._id}`);
            if (args.epic) {
                console.log(`  Epic Link:   ${args.epic}`);
            }
            if (Object.keys(args.extraFields).length) {
                console.log(`  Extra Fields: ${JSON.stringify(args.extraFields)}`);
            }
            console.log(`  Description (first 200 chars):`);
            console.log(`    ${riskDescriptionFormatted(threat, args.format, args.tmUri).slice(0, 200)}...`);
            console.log();
            continue;
        }

        const answer = (await ask('\nOpen JIRA? [Y/N]: ')).toUpperCase();
        if (answer === 'Y' || answer === 'YES') {
            const extra = { ...args.extraFields };
            if (args.epic) extra['Epic Link'] = args.epic;
            const url = await buildRiskReviewUrl(
                client,
                args.dest,
                args.issueType,
                threat,
                args.tmUri,
                extra,
            );
            openUrl(url);
            console.log(url);
        }

        const key = (await ask('Enter [JIRA KEY] to link ticket into threat model, or press [ENTER] to continue: ')).toUpperCase();
        if (key) {
            const ticketRef = `${args.jira}/browse/${key}`;
            updateThreatWithRef(threat, ticketRef);
        }
    }
}

main().catch(err => { console.error(err); process.exit(1); });
