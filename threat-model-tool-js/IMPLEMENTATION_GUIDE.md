# Complete Implementation Guide: Python to TypeScript Port

> **UPDATE (Feb 2026):** The core classes described here have been implemented. This guide remains as a reference for completing the remaining output formats and integration tests.

## Goal: 99% Output Similarity with Python Implementation

This guide provides step-by-step instructions to complete the TypeScript port of the threat model tool, matching the Python output format.

---

## Part 1: Core Data Model Classes

### 1.1 SecurityObjective.ts

**Python Reference**: `threatmodel_data.py` lines 257-305

```typescript
import { BaseThreatModelObject } from './BaseThreatModelObject.js';
import { REFID } from './REFID.js';

export class SecurityObjective extends BaseThreatModelObject {
    contributesTo: REFID[] = [];
    scope: any;
    group: string;
    priority: string = "High";
    inScope: boolean = true;
    private _treeImage: boolean = true;

    constructor(dictData: Record<string, any>, parent: BaseThreatModelObject) {
        super(dictData, parent);
        this.scope = parent;
        this.group = dictData.group;

        if (!dictData.group) {
            throw new Error(`SecurityObjective ${dictData.ID || 'undefined'} needs a 'group' attribute${this.getFileAndLineErrorMessage()}`);
        }

        // Handle contributesTo references
        if (dictData.contributesTo) {
            for (const dict2 of dictData.contributesTo) {
                if (dict2.REFID) {
                    this.contributesTo.push(new REFID(dict2, this));
                }
            }
        }
    }

    get treeImage(): boolean {
        // Check if there are any threats impacting this objective
        const root = this.getRoot() as any;
        const threats = root.getAllDown('threats');
        
        for (const threat of threats) {
            if (threat.impactedSecObjs) {
                for (const impactedSecObj of threat.impactedSecObjs) {
                    if (impactedSecObj.id === this.id || impactedSecObj.REFID === this.id) {
                        return this._treeImage;
                    }
                }
            }
        }
        return false;
    }

    set treeImage(value: boolean) {
        this._treeImage = value;
    }

    /**
     * Generate markdown link with anchor for impact reference
     */
    linkedImpactMDText(): string {
        return `<code><a href="#${this.anchor}">${this._id}</a></code>`;
    }

    /**
     * Generate markdown text for contributesTo relationship
     */
    contributedToMDText(): string {
        return `<code><a href="#${this.anchor}">${this._id}</a></code> *(${this.title})*`;
    }

    printAsText(): string {
        return `\nID: ${this.id} \nDescription: ${this.description}`;
    }

    shortText(): string {
        const firstPara = this.description.split("\n")[0];
        return `*${this.id}*\n(${firstPara})`;
    }
}
```

---

### 1.2 Countermeasure.ts

**Python Reference**: `threatmodel_data.py` lines 309-342

```typescript
import { BaseThreatModelObject } from './BaseThreatModelObject.js';

export class Countermeasure extends BaseThreatModelObject {
    threat: any;
    inPlace?: boolean;
    public?: boolean;
    operational: boolean = false;
    private _operator: string = "UNDEFINED";

    constructor(dictData: Record<string, any>, threat: any) {
        super(dictData, threat);
        this.threat = threat;

        const requiredKeys = ["inPlace", "public", "description", "title"];
        for (const key of requiredKeys) {
            if (!(key in dictData) || dictData[key] === null) {
                throw new Error(`Countermeasure needs a '${key}' attribute${this.getFileAndLineErrorMessage()}`);
            }
        }
    }

    printAsText(): string {
        return `\nID: ${this.id} \nDescription: ${this.description}`;
    }

    /**
     * Return RAG (Red/Amber/Green) style class name
     */
    RAGStyle(): string {
        return this.inPlace ? "countermeasureIP" : "countermeasureNIP";
    }

    /**
     * Return colors for PlantUML diagrams
     */
    statusColors(): { border: string; fill: string } {
        const inPlace = { border: '#82B366', fill: '#D5E8D4' };
        const notInPlace = { border: '#D6B656', fill: '#FFF2CC' };
        return this.inPlace ? inPlace : notInPlace;
    }

    get operator(): string {
        return this._operator;
    }

    set operator(value: string) {
        if (value) {
            this._operator = value;
        }
    }
}
```

---

### 1.3 Threat.ts

**Python Reference**: `threatmodel_data.py` lines 344-585

```typescript
import { BaseThreatModelObject } from './BaseThreatModelObject.js';
import { Countermeasure } from './Countermeasure.js';
import { REFID } from './REFID.js';
import { TMCVSS } from './CVSS.js';

export class Threat extends BaseThreatModelObject {
    countermeasures: (Countermeasure | REFID)[] = [];
    assets: REFID[] = [];
    impactedSecObjs: REFID[] = [];
    attackers: REFID[] = [];
    threatModel: any;
    attack?: string;
    threatType?: string;
    impactDesc?: string;
    fullyMitigated?: boolean;
    cvssObject: TMCVSS | null = null;
    private _ticketLink?: string;

    constructor(dictData: Record<string, any>, tm: any, publicFlag: boolean = false) {
        super(dictData, tm);
        
        this.threatModel = tm;

        if ('description' in dictData) {
            throw new Error(`description is not allowed in Threat ${this.id}, please use 'attack' instead (file: "${tm.fileName}")`);
        }

        // Set defaults
        if (!dictData.CVSS) {
            dictData.CVSS = { base: 'TODO CVSS', vector: '' };
        }
        if (!('fullyMitigated' in dictData)) {
            dictData.fullyMitigated = false;
        }

        // Process attributes
        for (const [k, v] of Object.entries(dictData)) {
            if (k === "ticketLink") {
                if (!publicFlag) {
                    this._ticketLink = v as string;
                }
            } else if (k === "countermeasures" && Array.isArray(v)) {
                for (const cmData of v) {
                    if (this.filterOutForPublicOrVersions(publicFlag, cmData)) {
                        continue;
                    }
                    if ("ID" in cmData) {
                        this.countermeasures.push(new Countermeasure(cmData, this));
                    } else if ("REFID" in cmData) {
                        this.countermeasures.push(new REFID(cmData, this));
                    } else {
                        throw new Error("REFID or ID needed to define a countermeasure in: " + this.id);
                    }
                }
            } else if (k === 'impactedSecObj' && Array.isArray(v)) {
                for (const secObjData of v) {
                    if ("REFID" in secObjData) {
                        this.impactedSecObjs.push(new REFID(secObjData, this));
                    } else {
                        throw new Error("REFID needed to reference an impacted Security Objective in: " + this.id);
                    }
                }
            } else if (k === "assets" && v !== null && Array.isArray(v)) {
                for (const assetData of v) {
                    this.assets.push(new REFID(assetData, this));
                }
            } else if (k === "attackers" && Array.isArray(v)) {
                for (const attackerData of v) {
                    if ("REFID" in attackerData) {
                        this.attackers.push(new REFID(attackerData, this));
                    } else {
                        throw new Error("REFID needed to reference an actual attacker ID in: " + this.id);
                    }
                }
            } else {
                try {
                    (this as any)[k] = v;
                } catch {
                    // Skip read-only properties
                }
            }
        }

        // Validate required fields
        if (!this.threatType) {
            throw new Error(`threatType required for ${this.id}`);
        }
        if (!('attack' in this) && this.attack !== "") {
            throw new Error(`attack instructions required for ${this.id} (even if empty use: 'attack: ""')`);
        }
        if (!this.title) {
            throw new Error(`title required for ${this.id}`);
        }

        // Initialize CVSS
        const cvssData = dictData.CVSS || {};
        if (cvssData.vector) {
            this.cvssObject = new TMCVSS(cvssData.vector);
        }
    }

    // Override description getter
    get description(): string {
        if (this.attack) {
            return `**Attack:** ${this.attack}<br/> **Impact:** ${this.impactDesc}`;
        }
        return 'undefined';
    }

    get attack_desc(): string | null {
        return this.attack || null;
    }

    get impact_desc(): string {
        let ret = "";
        if (this.impactDesc) {
            ret += this.impactDesc + "<br/> ";
        }
        if (this.impactedSecObjs) {
            for (const secObj of this.impactedSecObjs) {
                try {
                    const resolved = secObj.resolve();
                    if (resolved && (resolved as any).linkedImpactMDText) {
                        ret += (resolved as any).linkedImpactMDText() + "<br/> ";
                    }
                } catch {
                    throw new Error(`Problem in impactedSecObj definition reference in ${secObj.id}`);
                }
            }
        }
        return ret;
    }

    get ticketLink(): string | undefined {
        return this._ticketLink;
    }

    set ticketLink(value: string) {
        this._ticketLink = value;
        this.originDict.ticketLink = value;
    }

    // Override title getter
    get title(): string {
        if (this._title) {
            return this._title;
        }
        return this.threatGeneratedTitle();
    }

    set title(value: string) {
        this._title = value;
    }

    getSmartScoreDesc(): string {
        if (this.cvssObject) {
            return this.cvssObject.getSmartScoreDesc();
        }
        return "TODO CVSS";
    }

    getSmartScoreVal(): number {
        if (this.cvssObject) {
            return this.cvssObject.getSmartScoreVal();
        }
        return 0.0;
    }

    getSmartScoreColor(): string {
        if (this.cvssObject) {
            return this.cvssObject.getSmartScoreColor();
        }
        return "gray";
    }

    threatGeneratedTitle(): string {
        let assetDesc = " in: ";
        if (this.assets && this.assets.length > 0) {
            for (const asset of this.assets) {
                const resolved = asset.resolve() as any;
                if (resolved) {
                    assetDesc += `${resolved.type || ''} ${resolved.title || ''}, `;
                }
            }
            return this.threatType + assetDesc.slice(0, -2);
        }
        return this.threatType || '';
    }

    get operational(): boolean {
        for (const cm of this.countermeasures) {
            if ((cm as any).operational) {
                return true;
            }
        }
        return false;
    }

    getOperationalCountermeasures(): Countermeasure[] {
        const ocmList: Countermeasure[] = [];
        for (const cm of this.countermeasures) {
            if ((cm as any).operational) {
                ocmList.push(cm as Countermeasure);
            }
        }
        return ocmList;
    }
}
```

---

### 1.4 Asset.ts, Attacker.ts, Assumption.ts, Scope.ts

**Python Reference**: `threatmodel_data.py` lines 587-628

```typescript
// Asset.ts
import { BaseThreatModelObject } from './BaseThreatModelObject.js';

export class Asset extends BaseThreatModelObject {
    type?: string;
    inScope: boolean = true;
    properties: Record<string, any> = {};

    constructor(dictData: Record<string, any>, parent: BaseThreatModelObject) {
        super(dictData, parent);
        
        if (!dictData || (!dictData.type && !dictData.ID)) {
            throw new Error(`Asset must have a 'type' or 'ID' property`);
        }

        this.type = dictData.type;
        this.inScope = dictData.inScope !== undefined ? dictData.inScope : true;
        this.properties = dictData.properties || {};
    }

    propertiesHTML(): string {
        let html = "<ul>";
        for (const [key, value] of Object.entries(this.properties)) {
            html += `<li style='margin: 0px 0;'><b>${key}:</b> &nbsp;${value}</li>`;
        }
        return html + "</ul>";
    }
}

// Attacker.ts
import { BaseThreatModelObject } from './BaseThreatModelObject.js';

export class Attacker extends BaseThreatModelObject {
    inScope: boolean = true;

    constructor(dictData: Record<string, any>, parent: BaseThreatModelObject) {
        super(dictData, parent);
        this.inScope = dictData.inScope !== undefined ? dictData.inScope : true;
    }
}

// Assumption.ts
import { BaseThreatModelObject } from './BaseThreatModelObject.js';

export class Assumption extends BaseThreatModelObject {
    constructor(dictData: Record<string, any>, parent: BaseThreatModelObject) {
        super(dictData, parent);
    }
}

// Scope.ts
import { BaseThreatModelObject } from './BaseThreatModelObject.js';

export class Scope extends BaseThreatModelObject {
    constructor(dictData: Record<string, any>, parent: BaseThreatModelObject) {
        super(dictData, parent);
    }
}
```

---

### 1.5 ThreatModel.ts (CRITICAL - with children support)

**Python Reference**: `threatmodel_data.py` lines 629-900+

```typescript
import fs from 'fs';
import yaml from 'js-yaml';
import path from 'path';
import { BaseThreatModelObject } from './BaseThreatModelObject.js';
import { Threat } from './Threat.js';
import { Asset } from './Asset.js';
import { SecurityObjective } from './SecurityObjective.js';
import { Attacker } from './Attacker.js';
import { Assumption } from './Assumption.js';
import { Scope } from './Scope.js';
import { REFID } from './REFID.js';

export class ThreatModel extends BaseThreatModelObject {
    fileName: string;
    publicAccess: boolean;
    versionsFilterStr: string | null;
    threats: Threat[] = [];
    assets: Asset[] = [];
    securityObjectives: SecurityObjective[] = [];
    attackers: Attacker[] = [];
    assumptions: Assumption[] = [];
    scope: Scope;
    analysis: string = "";
    schemaVersion: number = 1;

    constructor(fileIn: string, parent: ThreatModel | null = null, publicFlag: boolean = false, versionsFilterStr: string | null = null) {
        // Load file first
        const fileName = fileIn;
        
        if (!fileName.endsWith('.yaml')) {
            throw new Error('input file needs to be .yaml');
        }

        console.log("processing:" + fileName);

        const tmDict = ThreatModel.tryLoadThreatModel(fileName);
        
        // Validate ID matches filename
        const expectedId = path.basename(fileName, '.yaml');
        if (tmDict.ID !== expectedId) {
            throw new Error(`Threat model ID '${tmDict.ID}' does not match filename '${expectedId}' in ${fileName}`);
        }

        // Initialize parent class
        super(tmDict, parent);

        this.fileName = fileName;
        this.publicAccess = publicFlag;
        this.versionsFilterStr = versionsFilterStr;
        this.originDict = tmDict;
        this._id = tmDict.ID;
        this.schemaVersion = tmDict.schemaVersion || 1;

        // Parse scope
        if (!tmDict.scope) {
            throw new Error(`Scope is empty in ${this.id}, please check the threat model file`);
        }
        this.scope = new Scope(tmDict.scope, this);

        // Parse analysis
        this.analysis = tmDict.analysis || tmDict['threat analysis'] || "";

        // Parse scope contents
        this.parseScope(tmDict.scope, publicFlag);

        // Parse threats
        if (tmDict.threats && Array.isArray(tmDict.threats)) {
            for (const threatDict of tmDict.threats) {
                if (this.filterOutForPublicOrVersions(publicFlag, threatDict)) {
                    continue;
                }
                const threat = new Threat(threatDict, this, publicFlag);
                this.threats.push(threat);
            }
        }

        // Parse child threat models
        if (tmDict.children && Array.isArray(tmDict.children)) {
            for (const childRef of tmDict.children) {
                if (childRef.REFID) {
                    // Load child threat model
                    const childPath = path.join(path.dirname(fileName), childRef.REFID, `${childRef.REFID}.yaml`);
                    if (fs.existsSync(childPath)) {
                        const childTM = new ThreatModel(childPath, this, publicFlag, versionsFilterStr);
                        // Child is automatically added to this.children by TreeNode constructor
                    }
                }
            }
        }

        // Resolve all REFIDs
        this.resolveReferences();
    }

    private parseScope(scopeDict: Record<string, any>, publicFlag: boolean): void {
        // Parse security objectives
        if (scopeDict.securityObjectives && Array.isArray(scopeDict.securityObjectives)) {
            for (const secObjDict of scopeDict.securityObjectives) {
                const secObj = new SecurityObjective(secObjDict, this);
                this.securityObjectives.push(secObj);
            }
        }

        // Parse assets
        if (scopeDict.assets && Array.isArray(scopeDict.assets)) {
            for (const assetDict of scopeDict.assets) {
                if (assetDict === null) {
                    throw new Error(`Asset is 'None' in ${this.id}`);
                }
                if (this.filterOutForPublicOrVersions(publicFlag, assetDict)) {
                    continue;
                }
                const asset = new Asset(assetDict, this);
                this.assets.push(asset);
            }
        }

        // Parse attackers
        if (scopeDict.attackers && Array.isArray(scopeDict.attackers)) {
            for (const attackerDict of scopeDict.attackers) {
                const attacker = new Attacker(attackerDict, this);
                this.attackers.push(attacker);
            }
        }

        // Parse assumptions
        if (scopeDict.assumptions && Array.isArray(scopeDict.assumptions)) {
            for (const assumptionDict of scopeDict.assumptions) {
                const assumption = new Assumption(assumptionDict, this);
                this.assumptions.push(assumption);
            }
        }
    }

    private resolveReferences(): void {
        // Resolve all REFIDs in the tree
        // This needs to happen after all objects are created
        this.resolveReferencesRecursive(this);
    }

    private resolveReferencesRecursive(node: any): void {
        // Check all array properties for REFIDs
        for (const key of Object.keys(node)) {
            const value = node[key];
            if (Array.isArray(value)) {
                for (let i = 0; i < value.length; i++) {
                    if (value[i] instanceof REFID) {
                        try {
                            value[i].replaceInParent(true);
                        } catch (e) {
                            // Some REFIDs might not resolve yet
                        }
                    }
                }
            }
        }

        // Recursively process children
        if (node.children) {
            for (const child of node.children) {
                this.resolveReferencesRecursive(child);
            }
        }
    }

    assetDir(): string {
        return path.join(path.dirname(this.fileName), 'assets');
    }

    /**
     * Get threats filtered by fullyMitigated status
     */
    getThreatsByFullyMitigated(fullyMitigated: boolean): Threat[] {
        const result: Threat[] = [];
        
        // Get from this model
        for (const threat of this.threats) {
            if (threat.fullyMitigated === fullyMitigated) {
                result.push(threat);
            }
        }

        // Get from child models
        for (const child of this.children) {
            if (child instanceof ThreatModel) {
                result.push(...child.getThreatsByFullyMitigated(fullyMitigated));
            }
        }

        return result;
    }

    /**
     * Get threats filtered by fullyMitigated AND operational status
     */
    getThreatsByFullyMitigatedAndOperational(fullyMitigated: boolean, operational: boolean): Threat[] {
        const result: Threat[] = [];
        
        for (const threat of this.threats) {
            if (threat.fullyMitigated === fullyMitigated && threat.operational === operational) {
                result.push(threat);
            }
        }

        // Get from child models
        for (const child of this.children) {
            if (child instanceof ThreatModel) {
                result.push(...child.getThreatsByFullyMitigatedAndOperational(fullyMitigated, operational));
            }
        }

        return result;
    }

    /**
     * Get all descendant threat models
     */
    getDescendantsTM(): ThreatModel[] {
        const result: ThreatModel[] = [];
        for (const child of this.children) {
            if (child instanceof ThreatModel) {
                result.push(child);
                result.push(...child.getDescendantsTM());
            }
        }
        return result;
    }

    private static tryLoadThreatModel(filename: string): Record<string, any> {
        try {
            const fileContents = fs.readFileSync(filename, 'utf8');
            return yaml.load(fileContents) as Record<string, any>;
        } catch (error) {
            throw new Error(`Error loading YAML file ${filename}: ${(error as Error).message}`);
        }
    }
}
```

---

## Part 2: Template Utilities

### 2.1 HeadingNumberer.ts (Singleton)

**Python Reference**: `template_utils.py` lines 64-205

```typescript
/**
 * HeadingNumberer - Singleton to track hierarchical heading numbers
 * Maintains state like 1, 1.1, 1.1.1, etc.
 */
export class HeadingNumberer {
    private static _instance: HeadingNumberer | null = null;
    private static _enabled: boolean = true;
    private static hierarchicalCounterLimit: number = 4;

    private counters: number[] = [];

    private constructor() {
        this.reset();
    }

    static getInstance(): HeadingNumberer {
        if (!HeadingNumberer._instance) {
            HeadingNumberer._instance = new HeadingNumberer();
        }
        return HeadingNumberer._instance;
    }

    reset(): void {
        this.counters = [0];
    }

    /**
     * Get the number for the given heading level
     * Returns empty string if disabled or level > limit
     */
    getNumber(level: number): string {
        if (!HeadingNumberer._enabled) {
            return "";
        }

        if (level > HeadingNumberer.hierarchicalCounterLimit) {
            return "";
        }

        // Adjust counters array to match level
        while (this.counters.length < level) {
            this.counters.push(0);
        }
        while (this.counters.length > level) {
            this.counters.pop();
        }

        // Increment current level
        this.counters[this.counters.length - 1]++;

        // Return formatted number (e.g., "1.2.3")
        return this.counters.join('.');
    }

    static enable(): void {
        HeadingNumberer._enabled = true;
    }

    static disable(): void {
        HeadingNumberer._enabled = false;
    }

    static isEnabled(): boolean {
        return HeadingNumberer._enabled;
    }

    static setLimit(limit: number): void {
        HeadingNumberer.hierarchicalCounterLimit = limit;
    }
}

// Global helper functions
export function enableHeadingNumbering(): void {
    HeadingNumberer.enable();
}

export function disableHeadingNumbering(): void {
    HeadingNumberer.disable();
}

export function resetHeadingNumbers(): void {
    HeadingNumberer.getInstance().reset();
}

export function isHeadingNumberingEnabled(): boolean {
    return HeadingNumberer.isEnabled();
}
```

### 2.2 TemplateUtils.ts

**Python Reference**: `template_utils.py` lines 248-392

```typescript
import { HeadingNumberer } from './HeadingNumberer.js';

/**
 * Safe property access with default value
 */
export function valueOr(obj: any, attr: string, alt: any): any {
    try {
        const value = obj[attr];
        return value !== undefined ? value : alt;
    } catch {
        return alt;
    }
}

/**
 * Create object anchor hash for HTML links
 * Format: parent._id.object._id or just object._id
 */
export function createObjectAnchorHash(tmObject: any): string {
    if (tmObject.parent && tmObject.parent._id && tmObject.parent.constructor.name === 'ThreatModel') {
        return `${tmObject.parent._id}.${tmObject._id}`;
    }
    return tmObject._id;
}

/**
 * Create title anchor hash (just lowercase and replace spaces)
 */
export function createTitleAnchorHash(title: string): string {
    return title.toLowerCase().replace(/\s+/g, '-').replace(/[^\w-]/g, '');
}

/**
 * Create markdown header with anchor and optional numbering
 * Matches Python: makeMarkdownLinkedHeader(level, title, ctx, skipTOC, tmObject)
 */
export function makeMarkdownLinkedHeader(
    level: number,
    title: string,
    ctx: any = {},
    skipTOC: boolean = false,
    tmObject: any = null
): string {
    const numberer = HeadingNumberer.getInstance();
    let number = "";
    
    if (HeadingNumberer.isEnabled()) {
        number = numberer.getNumber(level);
        if (number) {
            number = number + " ";
        }
    }

    // Create anchor
    let anchor = "";
    if (tmObject) {
        anchor = createObjectAnchorHash(tmObject);
    } else {
        anchor = createTitleAnchorHash(title);
    }

    // Build header
    const hashes = '#'.repeat(level);
    const skipTOCDiv = skipTOC ? "  <div class='skipTOC'></div>" : "";
    
    return `${hashes} ${number}${title}${skipTOCDiv} <a id='${anchor}'></a>\n`;
}

/**
 * Render nested markdown list from data structure
 */
export function renderNestedMarkdownList(
    data: any[],
    level: number = 0,
    firstIndent: string | null = null
): string {
    const lines: string[] = [];
    const indent = firstIndent !== null ? firstIndent : "  ".repeat(level);

    for (const item of data) {
        if (typeof item === 'string') {
            lines.push(`${indent}- ${item}`);
        } else if (Array.isArray(item)) {
            lines.push(renderNestedMarkdownList(item, level + 1, indent + "  "));
        } else if (typeof item === 'object') {
            for (const [key, value] of Object.entries(item)) {
                lines.push(`${indent}- **${key}:**`);
                if (Array.isArray(value)) {
                    lines.push(renderNestedMarkdownList(value, level + 1, indent + "  "));
                } else {
                    lines.push(`${indent}  ${value}`);
                }
            }
        }
    }

    return lines.join('\n');
}

/**
 * Strip markdown formatting from text
 */
export function unmark(text: string): string {
    if (!text) return "";
    
    // Remove markdown links [text](url) -> text
    text = text.replace(/\[([^\]]+)\]\([^\)]+\)/g, '$1');
    
    // Remove emphasis
    text = text.replace(/\*\*([^*]+)\*\*/g, '$1');
    text = text.replace(/\*([^*]+)\*/g, '$1');
    text = text.replace(/__([^_]+)__/g, '$1');
    text = text.replace(/_([^_]+)_/g, '$1');
    
    // Remove code
    text = text.replace(/`([^`]+)`/g, '$1');
    
    // Remove headers
    text = text.replace(/^#+\s*/gm, '');
    
    return text;
}

/**
 * Clean markdown text by removing links and references
 */
export function cleanMarkdownText(text: string): string {
    if (!text) return "";
    
    // Transform markdown links to text only
    text = text.replace(/\[([^\]]+)\]\([^\)]+\)/g, '$1');
    
    // Delete from "**Refs:" till end
    text = text.replace(/\*\*Refs?:.*$/s, '');
    
    return text;
}

/**
 * True/false mark for HTML
 */
export function trueOrFalseMark(value: boolean): string {
    return value 
        ? '<span style="color:green;">&#10004;</span>' 
        : '&#10060;';
}

/**
 * Page break marker
 */
export const PAGEBREAK = '<div class="pagebreak"></div>';
```

---

## Part 3: Core Renderers (lib_py.ts)

This is the MOST CRITICAL file - generates the actual markdown output.

**Python Reference**: `template/lib_py.py` (496 lines)

Create `src/renderers/lib_py.ts`:

```typescript
import { ThreatModel } from '../core/ThreatModel.js';
import { Threat } from '../core/Threat.js';
import { makeMarkdownLinkedHeader, PAGEBREAK, createObjectAnchorHash } from '../template/TemplateUtils.js';
import * as html from 'html-escaper';

/**
 * Render executive summary section
 * Python reference: lib_py.py lines 53-99
 */
export function executiveSummary(tmo: ThreatModel, headerLevel: number = 1, ctx: any = {}): string {
    const unmitNoOp = tmo.getThreatsByFullyMitigatedAndOperational(false, false);
    const mitigated = tmo.getThreatsByFullyMitigated(true);
    const unmitigated = tmo.getThreatsByFullyMitigated(false);

    const lines: string[] = [];
    
    lines.push(makeMarkdownLinkedHeader(headerLevel + 1, "Executive Summary", ctx, false));
    lines.push("> This section contains an executive summary of the threats and their mitigation status.\n");

    if (unmitNoOp.length < 1) {
        lines.push("**No unmitigated threats without operational countermeasures were identified**");
    } else {
        lines.push(`There are **${unmitNoOp.length}** unmitigated threats without proposed operational controls.<br/>`);
        lines.push('<div markdown="1">');
        lines.push('<table markdown="block" style="print-color-adjust: exact; -webkit-print-color-adjust: exact;">');
        lines.push("<tr><th>Threat ID</th><th>Severity</th></tr>");
        
        for (const threat of unmitNoOp) {
            const anchor = createObjectAnchorHash(threat);
            const cvssColor = threat.getSmartScoreColor();
            const cvssDesc = threat.getSmartScoreDesc();
            const parentId = threat.parent?._id || '';
            
            const cvssTd = `<td style="background-color: ${cvssColor}; " > <span markdown="block" style="font-weight:bold; color:white;"><strong>${cvssDesc}</strong></span> </td>`;
            
            let row = '<tr markdown="block"><td>';
            row += `<a href="#${anchor}">${parentId}.<br/>${threat._id}</a>`;
            
            if (threat.ticketLink) {
                row += `<br/><a href="${html.escape(threat.ticketLink)}"> Ticket link  </a>`;
            }
            
            row += `${cvssTd}</tr>`;
            lines.push(row);
        }
        
        lines.push("</table>");
        lines.push("</div>");
    }

    return lines.join('\n');
}

/**
 * Render threats summary table
 * Python reference: lib_py.py - threats_summary function
 */
export function threatsSummary(tmo: ThreatModel, headerLevel: number = 1, ctx: any = {}): string {
    const allThreats = tmo.threats;
    const descendantTMs = tmo.getDescendantsTM();
    
    for (const childTM of descendantTMs) {
        allThreats.push(...childTM.threats);
    }

    const unmitigated = allThreats.filter(t => !t.fullyMitigated);
    const unmitNoOp = allThreats.filter(t => !t.fullyMitigated && !t.operational);

    const lines: string[] = [];
    lines.push(makeMarkdownLinkedHeader(headerLevel + 2, "Threats Summary", ctx, false));
    lines.push(`There are a total of **${allThreats.length}** identified threats of which **${unmitigated.length}** are not fully mitigated by default, and  **${unmitNoOp.length}** are unmitigated without proposed operational controls.<br/>`);
    
    lines.push('<div markdown="1">');
    lines.push('<table markdown="block" style="print-color-adjust: exact; -webkit-print-color-adjust: exact;">');
    lines.push("<tr><th>Threat ID</th><th>CVSS</th><th>Mitigation Status</th></tr>");

    for (const threat of allThreats) {
        const anchor = createObjectAnchorHash(threat);
        const parentId = threat.parent?._id || '';
        const cvssColor = threat.getSmartScoreColor();
        const cvssDesc = threat.getSmartScoreDesc();
        
        let mitigationStatus = "Vulnerable";
        let statusColor = "#F8CECC";
        
        if (threat.fullyMitigated) {
            mitigationStatus = "Mitigated";
            statusColor = "#D5E8D4";
        }

        let row = '<tr markdown="block">';
        row += `<td><a href="#${anchor}">${parentId}.<br/>${threat._id}</a></td>`;
        row += `<td style="background-color: ${cvssColor}; " ><span markdown="block" style="font-weight:bold; color:white;"><strong>${cvssDesc}</strong></span></td>`;
        row += `<td style="background-color: ${statusColor};text-align: center ">${mitigationStatus}</td>`;
        row += '</tr>';
        
        lines.push(row);
    }

    lines.push("</table></div>");
    return lines.join('\n');
}

/**
 * Render security objectives section
 */
export function renderSecurityObjectives(tmo: ThreatModel, headerLevel: number = 2, ctx: any = {}): string {
    const lines: string[] = [];
    
    lines.push(makeMarkdownLinkedHeader(headerLevel, `${tmo.title} security objectives`, ctx));
    
    // Group by group attribute
    const groups: Record<string, any[]> = {};
    for (const secObj of tmo.securityObjectives) {
        const group = secObj.group || 'Other';
        if (!groups[group]) {
            groups[group] = [];
        }
        groups[group].push(secObj);
    }

    // Render grouped list
    for (const [groupName, objectives] of Object.entries(groups)) {
        lines.push(`**${groupName}:**\n`);
        for (const obj of objectives) {
            lines.push(`- <a href="#${obj.anchor}">${obj.title}</a>\n`);
        }
        lines.push("");
    }

    // Add diagram reference
    lines.push("**Diagram:**");
    lines.push('<img src="img/secObjectives.svg"/>');
    lines.push("**Details:**\n");

    // Render each objective
    for (const secObj of tmo.securityObjectives) {
        lines.push(makeMarkdownLinkedHeader(headerLevel + 1, `${secObj.title} (<code>${secObj._id}</code>)`, ctx, false, secObj));
        lines.push(`\n${secObj.description}`);
        
        if (secObj.priority) {
            lines.push(`**Priority:** ${secObj.priority}\n`);
        }

        // Contributes to
        if (secObj.contributesTo && secObj.contributesTo.length > 0) {
            lines.push("**Contributes to:**\n");
            for (const ref of secObj.contributesTo) {
                const resolved = ref.resolve();
                if (resolved) {
                    lines.push(`- <code><a href="#${resolved.anchor}">${resolved._id}</a></code> *(${resolved.title})*\n`);
                }
            }
        }

        // Attack tree diagram
        if (secObj.treeImage) {
            lines.push("**Attack tree:**\n");
            lines.push(`<img src="img/secObjectives/${secObj._id}.svg"/>`);
            lines.push('<img src="img/legend_SecObjTree.svg" width="400"/>');
        }
        
        lines.push("<hr/>\n");
    }

    return lines.join('\n');
}

// Continue with more renderers...
// renderThreats(), renderAssets(), etc.
```

---

## Part 4: PlantUML Generators

### 4.1 AttackTreeGenerator.ts

**Python Reference**: `createThreatPlantUMLDiagrams.py` and `TM_AttackTreePlantUMLDiagram.py`

This generates GraphViz DOT format (not simple PlantUML):

```typescript
import { ThreatModel } from '../core/ThreatModel.js';
import { Threat } from '../core/Threat.js';

export class AttackTreeGenerator {
    /**
     * Generate attack tree in DOT format
     * Output format matches Python exactly
     */
    static generate(tmo: ThreatModel): string {
        const lines: string[] = [];
        
        lines.push('@startuml');
        lines.push('digraph G {');
        lines.push('  rankdir="RL";');
        lines.push('  node [shape=plaintext, fontname="Arial" fontsize="12", align="left"];');
        lines.push('');

        // Render threat model node
        lines.push(this.renderThreatModelNode(tmo));

        // Render all threats
        for (const threat of tmo.threats) {
            lines.push(this.renderThreatNode(threat, tmo));
        }

        // Render child threat models
        for (const child of tmo.children) {
            if (child.constructor.name === 'ThreatModel') {
                lines.push(this.renderThreatModelNode(child as any));
                for (const threat of (child as any).threats) {
                    lines.push(this.renderThreatNode(threat, child as any));
                }
            }
        }

        lines.push('}');
        lines.push('@enduml');
        
        return lines.join('\n');
    }

    private static renderThreatModelNode(tmo: ThreatModel): string {
        const lines: string[] = [];
        
        lines.push(`"${tmo._id}" [fillcolor="#bae9ff", style=filled, shape=ellipse, color="#B85450",`);
        lines.push(' label=');
        lines.push(' <<table border="0" cellborder="0" cellspacing="0">');
        lines.push('   <tr><td align="left">');
        
        // Split title into multiple lines if needed
        const titleLines = this.wrapText(tmo.title, 30);
        for (let i = 0; i < titleLines.length; i++) {
            lines.push(`     <b>${this.escapeHtml(titleLines[i])}</b>`);
            if (i < titleLines.length - 1) {
                lines.push('<br/>');
            }
        }
        
        lines.push('   </td></tr>');
        lines.push(' </table>>]');
        
        return lines.join('\n');
    }

    private static renderThreatNode(threat: Threat, tmo: ThreatModel): string {
        const lines: string[] = [];
        
        const mitigationStatus = threat.fullyMitigated ? "Mitigated" : "Vulnerable";
        const fillColor = threat.fullyMitigated ? "#D5E8D4" : "#F8CECC";
        const borderColor = threat.fullyMitigated ? "#82B366" : "#E06666";
        const cvssColor = threat.getSmartScoreColor();
        const cvssDesc = threat.getSmartScoreDesc();

        lines.push(`"${threat._id}" [ fillcolor="${fillColor}", style=filled, shape=polygon, color="${borderColor}", penwidth=2,`);
        lines.push(`    URL="../index.html#${threat._id}",  target="_top",`);
        lines.push('    label=');
        lines.push('    <<table border="0" cellborder="0" cellspacing="0" width="530">');
        lines.push(`     <tr><td align="left"><b>${this.escapeHtml(threat.title)} <i>-${mitigationStatus}</i></b>`);
        lines.push(`     </td>  <td BGCOLOR="${cvssColor}">${cvssDesc}</td></tr>`);
        
        // Attack description
        const attackDesc = this.cleanMarkdownText(threat.attack || '');
        const wrappedAttack = this.wrapText(attackDesc, 80);
        lines.push(`     <tr><td align="center" COLSPAN="2">${this.escapeHtml(wrappedAttack.join(' '))}</td></tr>`);
        
        lines.push('   </table>>');
        lines.push('];');
        lines.push('');

        // Render countermeasures
        let cmIndex = 0;
        for (const cm of threat.countermeasures) {
            const cmResolved = 'REFID' in cm ? (cm as any).resolve() : cm;
            if (!cmResolved) continue;

            const colors = cmResolved.statusColors();
            const cmId = `${threat._id}_countermeasure${cmIndex}`;
            
            lines.push(`"${cmId}" [`);
            lines.push(`    fillcolor="${colors.fill}", style=filled, shape=polygon, penwidth=2,`);
            lines.push(`    color="${colors.border}",`);
            lines.push('    label=');
            lines.push('    <<table border="0" cellborder="0" cellspacing="0" width="530">');
            lines.push('      <tr><td align="left">');
            lines.push(`        <b>${this.escapeHtml(cmResolved.title)}</b><br/><br/>`);
            
            const desc = this.cleanMarkdownText(cmResolved.description || '');
            const wrappedDesc = this.wrapText(desc, 80);
            lines.push(`        ${this.escapeHtml(wrappedDesc.join(' '))}`);
            
            lines.push('      </td></tr>');
            lines.push('    </table>>');
            lines.push(']');
            lines.push('');
            lines.push(`"${cmId}" -> "${threat._id}" [label = " mitigates", style="solid", color="green", penwidth=2]`);
            
            cmIndex++;
        }

        // Connect threat to threat model
        lines.push(`"${threat._id}" -> "${tmo._id}" [label="impacts ", color="#B85450", style="solid", penwidth=2]`);
        
        return lines.join('\n');
    }

    private static escapeHtml(text: string): string {
        return text
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }

    private static cleanMarkdownText(text: string): string {
        // Remove markdown formatting
        return text
            .replace(/\[([^\]]+)\]\([^\)]+\)/g, '$1')
            .replace(/\*\*/g, '')
            .replace(/\*/g, '')
            .replace(/__/g, '')
            .replace(/_/g, '');
    }

    private static wrapText(text: string, width: number): string[] {
        const words = text.split(/\s+/);
        const lines: string[] = [];
        let currentLine = '';

        for (const word of words) {
            if (currentLine.length + word.length + 1 <= width) {
                currentLine += (currentLine ? ' ' : '') + word;
            } else {
                if (currentLine) lines.push(currentLine);
                currentLine = word;
            }
        }
        if (currentLine) lines.push(currentLine);

        return lines;
    }
}
```

---

## Part 5: Main Report Generator

### 5.1 ReportGenerator.ts

**Python Reference**: `report_generator.py` and `fullBuildSingleTM.py`

```typescript
import fs from 'fs';
import path from 'path';
import { ThreatModel } from './core/ThreatModel.js';
import { executiveSummary, threatsSummary, renderSecurityObjectives } from './renderers/lib_py.js';
import { AttackTreeGenerator } from './puml/AttackTreeGenerator.js';
import { resetHeadingNumbers } from './template/HeadingNumberer.js';

export class ReportGenerator {
    /**
     * Generate full report for a threat model
     */
    static generate(
        tmo: ThreatModel,
        template: string = 'full',
        outputDir: string,
        ctx: any = {}
    ): void {
        const baseFileName = tmo._id;
        const mdOutFileName = path.join(outputDir, `${baseFileName}.md`);

        // Prepare output directory
        fs.mkdirSync(outputDir, { recursive: true });
        fs.mkdirSync(path.join(outputDir, 'img'), { recursive: true });

        // Reset heading numbers
        resetHeadingNumbers();

        // Set context defaults
        const context = {
            processToc: true,
            process_prepost_md: true,
            process_heading_numbering: true,
            mainTitle: ctx.mainTitle || null,
            ...ctx
        };

        // Render report
        let mdReport = this.renderFullReport(tmo, context);

        // Process heading numbers
        if (context.process_heading_numbering) {
            mdReport = this.processHeadingNumbers(mdReport);
        }

        // Inject TOC
        if (context.processToc) {
            const toc = this.generateTOC(mdReport);
            mdReport = mdReport.replace('__TOC_PLACEHOLDER__', toc);
        }

        // Write markdown file
        fs.writeFileSync(mdOutFileName, mdReport, 'utf8');
        console.log(`Generated: ${mdOutFileName}`);

        // Generate PlantUML diagrams
        this.generatePlantUML(tmo, outputDir);
    }

    private static renderFullReport(tmo: ThreatModel, ctx: any): string {
        const lines: string[] = [];
        
        // Opening div
        lines.push("<div markdown=\"block\" class='current'>\n\n");

        // Title
        const title = ctx.mainTitle || `${tmo.title} Threat Model`;
        lines.push(`# ${title}   <div class='skipTOC'></div> <a id='${tmo._id}'></a>\n`);
        lines.push(`\nVersion: ${tmo.originDict.version}\n`);
        lines.push(`Last update: ${new Date().toISOString().split('T')[0].replace(/-/g, '-')} ${new Date().toTimeString().split(' ')[0]}\n`);
        
        if (tmo.originDict.authors) {
            lines.push(`Authors: ${tmo.originDict.authors}\n`);
        }

        lines.push('\n<div class="pagebreak"></div>\n\n');

        // TOC placeholder
        lines.push('## Table of contents   <div class=\'skipTOC\'></div> <a id=\'table-of-contents\'></a>\n\n');
        lines.push('__TOC_PLACEHOLDER__\n');
        lines.push('<div class="pagebreak"></div>\n\n');

        // Executive Summary
        lines.push(executiveSummary(tmo, 0, ctx));
        lines.push('<div class="pagebreak"></div>\n\n');

        // Threats Summary
        lines.push(threatsSummary(tmo, 0, ctx));

        // Scope section
        lines.push(`# ${tmo.title} - scope of analysis <a id='${tmo._id.toLowerCase()}-scope-of-analysis'></a>\n\n`);
        
        // Overview
        if (tmo.scope.description || tmo.originDict.scope?.description) {
            lines.push(`## ${tmo.title} Overview <a id='${tmo._id.toLowerCase()}-overview'></a>\n\n`);
            lines.push(tmo.scope.description || tmo.originDict.scope.description);
            lines.push('\n\n');
        }

        // Security Objectives
        lines.push(renderSecurityObjectives(tmo, 2, ctx));

        // More sections...
        // Linked threat models, attackers, assumptions, assets, threats, etc.

        lines.push('\n</div>');
        return lines.join('\n');
    }

    private static processHeadingNumbers(markdown: string): string {
        // This adds numbers to headings
        // Implementation similar to Python report_generator.py lines 134-200
        const lines = markdown.split('\n');
        const result: string[] = [];
        let inFence = false;

        for (const line of lines) {
            // Detect code fences
            if (line.match(/^\s*(```|~~~)/)) {
                inFence = !inFence;
                result.push(line);
                continue;
            }

            if (inFence) {
                result.push(line);
                continue;
            }

            // Check for heading
            const match = line.match(/^(#{1,6})\s+(.*)$/);
            if (match) {
                const hashes = match[1];
                const rest = match[2];
                
                // Skip if already numbered or has skipTOC
                if (rest.match(/^\d+/) || rest.includes('skipTOC')) {
                    result.push(line);
                    continue;
                }

                // This would need HeadingNumberer integration
                result.push(line);
            } else {
                result.push(line);
            }
        }

        return result.join('\n');
    }

    private static generateTOC(markdown: string): string {
        // Extract headings and build TOC
        // Python reference: This is done via markdown extension
        const lines: string[] = [];
        lines.push('<div markdown="1">\n');
        
        // Parse headings
        const headingRegex = /^(#{1,6})\s+([^\n<]+)/gm;
        let match;
        
        while ((match = headingRegex.exec(markdown)) !== null) {
            const level = match[1].length;
            const title = match[2].trim();
            
            // Skip if has skipTOC
            if (title.includes('skipTOC')) continue;
            
            const indent = '&nbsp;&nbsp;'.repeat(level - 1);
            const anchor = title.toLowerCase().replace(/\s+/g, '-').replace(/[^\w-]/g, '');
            
            const bold = level <= 2 ? '**' : level === 3 ? '***' : '';
            lines.push(`${indent}  ${bold}[${title}](#${anchor}){.tocLink}${bold}\n`);
        }

        lines.push('\n</div>');
        return lines.join('');
    }

    private static generatePlantUML(tmo: ThreatModel, outputDir: string): void {
        // Generate attack tree
        const attackTree = AttackTreeGenerator.generate(tmo);
        const pumlPath = path.join(outputDir, 'img', `${tmo._id}_ATTACKTREE.puml`);
        fs.writeFileSync(pumlPath, attackTree, 'utf8');
        console.log(`Generated: ${pumlPath}`);

        // Generate other diagrams...
    }
}
```

---

## Part 6: Testing Strategy

### 6.1 Create Test Suite

Create `tests/integration/fullFeature.test.ts`:

```typescript
import { ThreatModel } from '../../src/core/ThreatModel.js';
import { ReportGenerator } from '../../src/ReportGenerator.js';
import fs from 'fs';
import path from 'path';

describe('FullFeature Integration Test', () => {
    test('should generate report matching Python output', () => {
        // Load threat model
        const yamlPath = '/workspaces/threat-model-tool/tests/exampleThreatModels/FullFeature/FullFeature.yaml';
        const tmo = new ThreatModel(yamlPath);

        // Generate report
        const outputDir = './test-output';
        ReportGenerator.generate(tmo, 'full', outputDir);

        // Load generated and expected
        const generated = fs.readFileSync(path.join(outputDir, 'FullFeature.md'), 'utf8');
        const expected = fs.readFileSync('/workspaces/threat-model-tool/build/FullFeature/FullFeature.md', 'utf8');

        // Compare (allowing for minor whitespace differences)
        const normalizeWhitespace = (str: string) => str.replace(/\s+/g, ' ').trim();
        const similarity = compareSimilarity(normalizeWhitespace(generated), normalizeWhitespace(expected));

        expect(similarity).toBeGreaterThan(0.99); // 99% similarity
    });
});

function compareSimilarity(str1: string, str2: string): number {
    // Simple line-by-line comparison
    const lines1 = str1.split('\n');
    const lines2 = str2.split('\n');
    
    let matches = 0;
    const maxLen = Math.max(lines1.length, lines2.length);
    
    for (let i = 0; i < maxLen; i++) {
        if (lines1[i] === lines2[i]) matches++;
    }
    
    return matches / maxLen;
}
```

---

## Part 7: Build Script

Create `scripts/build-threat-model.ts`:

```typescript
#!/usr/bin/env node
import { ThreatModel } from './src/core/ThreatModel.js';
import { ReportGenerator } from './src/ReportGenerator.js';
import { execSync } from 'child_process';
import path from 'path';

const args = process.argv.slice(2);
const yamlFile = args[0];
const outputDir = args[1] || './output';

if (!yamlFile) {
    console.error('Usage: build-threat-model.ts <yaml-file> [output-dir]');
    process.exit(1);
}

// Load and generate
const tmo = new ThreatModel(yamlFile);
ReportGenerator.generate(tmo, 'full', outputDir);

// Run PlantUML via Docker
const imgDir = path.join(outputDir, 'img');
console.log('Generating PlantUML diagrams...');

try {
    execSync(`docker run --rm -v ${path.resolve(imgDir)}:/data plantuml/plantuml:sha-d2b2bcf *.puml -svg -v`, {
        stdio: 'inherit'
    });
} catch (error) {
    console.warn('PlantUML generation failed (Docker required)');
}

console.log('Done!');
```

---

## Implementation Checklist

### Week 1: Core Model
- [ ] Complete all core classes (1-2 days)
- [ ] Test with FullFeature.yaml
- [ ] Verify REFID resolution
- [ ] Test nested models (SubComponent)

### Week 2: Renderers
- [ ] Complete lib_py.ts (2-3 days)
- [ ] Test output sections individually
- [ ] Match HTML table format exactly
- [ ] Verify color codes

### Week 3: PlantUML & Integration
- [ ] Complete PlantUML generators (1 day)
- [ ] Report generator orchestration (1 day)
- [ ] TOC generation (1 day)
- [ ] End-to-end testing (2 days)

### Week 4: Polish & Testing
- [ ] Compare outputs (99% match)
- [ ] Fix whitespace/formatting
- [ ] Documentation
- [ ] Final validation

---

## Key Success Metrics

1. **Structure Match**: All sections present in correct order
2. **HTML Format**: Tables, spans, divs match exactly
3. **PlantUML**: DOT format with correct colors and structure
4. **TOC**: Hierarchical numbering (1, 1.1, 1.1.1)
5. **CVSS**: Colors and scores match
6. **Nested Models**: SubComponent integrated correctly
7. **Overall Similarity**: 99%+ match with Python output

---

## Tips for Implementation

1. **Work incrementally**: Test each class immediately
2. **Compare output frequently**: Use diff tools
3. **Copy Python string templates**: Many sections are just string formatting
4. **Use the Python code as reference**: It's well-structured
5. **Test with FullFeature.yaml**: It has all features
6. **Focus on output format**: The logic is straightforward, formatting matters

---

## Final Notes

The vast majority of this is **string manipulation and templating**. The Python code is clean and well-organized. Follow the patterns, replicate the string formatting exactly, and test frequently.

The most time-consuming parts are:
1. HTML table generation (precise formatting)
2. PlantUML DOT format (exact syntax)
3. TOC generation (hierarchical numbering)

Everything else is relatively straightforward object mapping and iteration.

Good luck with the implementation! The foundation is solid - now it's execution.
