const THREAT_ID_RE = /^\s*-\s*ID:\s+([A-Z0-9_]+)\s*$/;
const TICKET_LINK_RE = /^\s*ticketLink:\s+['\"]?([^'\"\s]+)['\"]?\s*$/;
const ISSUE_KEY_RE = /[A-Z][A-Z0-9]+-\d+/;

export function parseThreatTicketMapFromYaml(yamlText: string): Record<string, string> {
    const map: Record<string, string> = {};
    let currentThreatId: string | null = null;

    for (const line of yamlText.split(/\r?\n/)) {
        const threatMatch = THREAT_ID_RE.exec(line);
        if (threatMatch) {
            currentThreatId = threatMatch[1];
            continue;
        }

        const ticketMatch = TICKET_LINK_RE.exec(line);
        if (!ticketMatch || !currentThreatId) {
            continue;
        }

        const issueKeyMatch = ISSUE_KEY_RE.exec(ticketMatch[1]);
        if (issueKeyMatch) {
            map[currentThreatId] = issueKeyMatch[0];
        }
    }

    return map;
}

export function mergeThreatTicketMaps(...maps: Array<Record<string, string>>): Record<string, string> {
    return Object.assign({}, ...maps);
}
