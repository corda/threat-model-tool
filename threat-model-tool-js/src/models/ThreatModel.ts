import fs from 'fs';
import yaml from 'js-yaml';
import path from 'path';
import BaseThreatModelObject from './BaseThreatModelObject.js';
import Threat from './Threat.js';
import Asset from './Asset.js';
import Countermeasure from './Countermeasure.js';
import SecurityObjective from './SecurityObjective.js';
import Attacker from './Attacker.js';
import Assumption from './Assumption.js';
import Scope from './Scope.js';
import REFID from './REFID.js';

export default class ThreatModel extends BaseThreatModelObject {
    fileName: string;
    publicAccess: boolean;
    versionsFilterStr: string | null;
    threats: Threat[] = [];
    assets: Asset[] = [];
    securityObjectives: SecurityObjective[] = [];
    attackers: Attacker[] = [];
    assumptions: Assumption[] = [];
    scope!: Scope;
    analysis: string = "";
    schemaVersion: number = 1;

    constructor(fileIn: string, parent: ThreatModel | null = null, publicFlag: boolean = false, versionsFilterStr: string | null = null) {
        const tmDict = fileIn && (fileIn.endsWith('.yaml') || fileIn.endsWith('.yml'))
            ? ThreatModel.loadYaml(fileIn)
            : {};
            
        super(tmDict, parent);

        this.fileName = fileIn;
        this.publicAccess = publicFlag;
        this.versionsFilterStr = versionsFilterStr;

        if (!tmDict.ID) {
            return;
        }

        this.originDict = tmDict;
        this._id = tmDict.ID;
        this.schemaVersion = tmDict.schemaVersion || 1;

        // Validate ID matches filename
        const expectedId = path.basename(fileIn, path.extname(fileIn));
        if (tmDict.ID !== expectedId) {
            console.warn(`Threat model ID '${tmDict.ID}' does not match filename '${expectedId}' in ${fileIn}`);
        }

        // Parse scope
        if (!tmDict.scope) {
            throw new Error(`Scope is empty in ${this.id}, please check the threat model file`);
        }
        this.scope = new Scope(tmDict.scope, this);

        // Parse analysis
        // Note: Python uses setattr with YAML keys as-is, so 'threat analysis' (with space)
        // becomes a different attribute than 'analysis'. hasattr(tmo, "analysis") is False
        // for YAML key "threat analysis". We match that behavior here.
        this.analysis = tmDict.analysis || "";

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
                    const childPath = path.join(path.dirname(fileIn), childRef.REFID, `${childRef.REFID}.yaml`);
                    if (fs.existsSync(childPath)) {
                        new ThreatModel(childPath, this, publicFlag, versionsFilterStr);
                    } else {
                        // Try same directory
                        const childPathSameDir = path.join(path.dirname(fileIn), `${childRef.REFID}.yaml`);
                        if (fs.existsSync(childPathSameDir)) {
                            new ThreatModel(childPathSameDir, this, publicFlag, versionsFilterStr);
                        }
                    }
                }
            }
        }
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

    assetDir(): string {
        return path.join(path.dirname(this.fileName), 'assets');
    }

    /**
     * Check if this is the root threat model (no parent)
     */
    isRoot(): boolean {
        return this.parent === null;
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

    public getAssetsByProps(props: Record<string, any>): Asset[] {
        const assets = this.getAllDown(Asset);
        return assets.filter(asset => {
            for (const [key, value] of Object.entries(props)) {
                if ((asset as any)[key] !== value) return false;
            }
            return true;
        });
    }

    public getOperationalGuideData(): Record<string, Countermeasure[]> {
        const guideData: Record<string, Countermeasure[]> = {};
        const threats = this.getAllDown(Threat).filter(t => t.operational === true);
        
        // extract all countermeasures
        const cms: Countermeasure[] = [];
        const operators = new Set<string>();
        
        for (const t of threats) {
            for (const c of t.countermeasures) {
                if (c instanceof Countermeasure && c.operational) {
                    cms.push(c);
                    operators.add(c.operator);
                }
            }
        }

        for (const op of operators) {
            guideData[op] = [];
        }

        for (const cm of cms) {
            guideData[cm.operator].push(cm);
        }

        return guideData;
    }

    private static loadYaml(filename: string): Record<string, any> {
        try {
            const fileContents = fs.readFileSync(filename, 'utf8');
            return yaml.load(fileContents) as Record<string, any>;
        } catch (error) {
            throw new Error(`Error loading YAML file ${filename}: ${(error as Error).message}`);
        }
    }
}
