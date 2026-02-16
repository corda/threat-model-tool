import BaseThreatModelObject from './BaseThreatModelObject.js';
import { TMCVSS } from './CVSS.js';
import Countermeasure from './Countermeasure.js';
import REFID from './REFID.js';

export default class Threat extends BaseThreatModelObject {
    countermeasures: (Countermeasure | REFID)[];
    assets: REFID[];
    impactedSecObjs: REFID[];
    attackers: REFID[];
    threatModel: any;
    attack?: string;
    threatType?: string;
    impactDesc?: string;
    fullyMitigated?: boolean;
    cvssObject: TMCVSS | null = null;
    ticketLink?: string;

    constructor(dictData: Record<string, any>, threatModel: any, publicAccess: boolean = false) {
        super(dictData, threatModel);
        
        this.countermeasures = [];
        this.assets = [];
        this.impactedSecObjs = [];
        this.attackers = [];
        this.threatModel = threatModel;

        if ('description' in dictData) {
            throw new Error(`description is not allowed in Threat ${this.id}, please use 'attack' instead`);
        }

        dictData.CVSS = dictData.CVSS || dictData.cvss || { base: 'TODO CVSS', vector: '' };
        this.cvssObject = new TMCVSS(dictData.CVSS);
        dictData.fullyMitigated = dictData.fullyMitigated !== undefined ? dictData.fullyMitigated : false;
        this.fullyMitigated = dictData.fullyMitigated;

        for (const [key, value] of Object.entries(dictData)) {
            if (key === 'ticketLink') {
                 if (!publicAccess) {
                    this.ticketLink = value as string;
                 }
            } else if (key === 'countermeasures') {
                for (const cmData of value as Record<string, any>[]) {
                    if (this.filterOutForPublicOrVersions(publicAccess, cmData)) {
                        continue;
                    } else if ('ID' in cmData) {
                        this.countermeasures.push(new Countermeasure(cmData, this));
                    } else if ('REFID' in cmData) {
                        this.countermeasures.push(new REFID(cmData, this));
                    } else {
                        throw new Error(`REFID or ID needed to define a countermeasure in: ${this.id}`);
                    }
                }
            } else if (key === 'impactedSecObj') {
                for (const secObjData of value as Record<string, any>[]) {
                    if ('REFID' in secObjData) {
                        this.impactedSecObjs.push(new REFID(secObjData, this));
                    } else {
                        throw new Error(`REFID needed to reference an impacted Security Objective in: ${this.id}`);
                    }
                }
            } else if (key === 'assets') {
                for (const assetData of value as Record<string, any>[]) {
                   this.assets.push(new REFID(assetData, this));
                }
            } else if (key === 'attackers') {
                for (const attackerData of value as Record<string, any>[]) {
                    if ('REFID' in attackerData) {
                        this.attackers.push(new REFID(attackerData, this));
                    } else {
                        throw new Error(`REFID needed to reference an actual attacker ID in: ${this.id}`);
                    }
                }
            } else {
                try {
                    (this as any)[key] = value;
                } catch {
                    // Skip read-only
                }
            }
        }

        if (!this.threatType) {
            throw new Error(`threatType required for ${this.id}`);
        }

        if (!this.attack && this.attack !== "") {
             throw new Error(`attack instructions required for ${this.id} (even if empty use: 'attack: ""')`);
        }

        if (!this.title) {
            throw new Error(`title required for ${this.id}`);
        }

        // CVSS already constructed above from the full dict
    }

    get description(): string {
        if (this.attack !== undefined) {
             return `**Attack:** ${this.attack}<br/> **Impact:** ${this.impactDesc}`;
        }
        return 'undefined';
    }

    get impact_desc(): string {
        let ret = "";
        if (this.impactDesc) {
            ret += this.impactDesc + "<br/> ";
        }
        if (this.impactedSecObjs) {
            for (const secObj of this.impactedSecObjs) {
                try {
                    const resolved = secObj.resolve() as any;
                    if (resolved && resolved.linkedImpactMDText) {
                        ret += resolved.linkedImpactMDText() + "<br/> ";
                    }
                } catch {
                    throw new Error(`Problem in impactedSecObj definition reference in ${secObj.id}`);
                }
            }
        }
        return ret;
    }

    getSmartScoreDesc(): string {
        return this.cvssObject ? this.cvssObject.getSmartScoreDesc() : 'TODO CVSS';
    }

    getSmartScoreVal(): number {
        const score = this.cvssObject ? this.cvssObject.getSmartScoreVal() : 0.0;
        return Number.isFinite(score) ? score : 0.0;
    }

    getSmartScoreColor(): string {
        return this.cvssObject ? this.cvssObject.getSmartScoreColor() : 'gray';
    }

    /** Mitigation status text matching Python output */
    statusDefaultText(): string {
        if (this.fullyMitigated) {
            return this.secureByDefault() ? 'Mitigated' : 'Not Secure by Default <br/>(Operational mitigation)';
        }
        return 'Vulnerable';
    }

    /** 
     * Secure by default means fully mitigated without operational countermeasures needed.
     * Matches Python: fullyMitigated and not hasOperationalCountermeasures()
     */
    secureByDefault(): boolean {
        if (!this.fullyMitigated) return false;
        return !this.hasOperationalCountermeasures();
    }

    /** Check if any countermeasure is marked as operational */
    hasOperationalCountermeasures(): boolean {
        for (const cm of this.countermeasures) {
            const resolved = (cm as any).resolve ? (cm as any).resolve() : cm;
            if (resolved && resolved.operational) return true;
        }
        return false;
    }

    private static readonly mitigatedColors = { border: '#82B366', fill: '#D5E8D4' };
    private static readonly inSecureByDefaultColors = { border: '#D6B656', fill: '#FFF2CC' };
    private static readonly notFullyMitigatedColors = { border: '#E06666', fill: '#F8CECC' };

    statusColors(): { border: string; fill: string } {
        if (this.fullyMitigated) {
            return this.secureByDefault() ? Threat.mitigatedColors : Threat.inSecureByDefaultColors;
        }
        return Threat.notFullyMitigatedColors;
    }

    threatGeneratedTitle(): string {
        const assetDesc = this.assets.length > 0 ? 
            this.assets.map(asset => {
                const resolved = asset.resolve();
                return `${(resolved as any)?.type || ''} ${(resolved as any)?.title || asset.REFIDValue || ''}`;
            }).join(', ') : '';
        return `${this.threatType} in: ${assetDesc}`;
    }

    get operational(): boolean {
        for (const cm of this.countermeasures) {
            const cmResolved = (cm as any).resolve ? (cm as any).resolve() : cm;
            if (cmResolved && cmResolved.operational) {
                return true;
            }
        }
        return false;
    }

    getOperationalCountermeasures(): Countermeasure[] {
        const ocmList: Countermeasure[] = [];
        for (const cm of this.countermeasures) {
            const cmResolved = (cm as any).resolve ? (cm as any).resolve() : cm;
            if (cmResolved && cmResolved.operational) {
                ocmList.push(cmResolved as Countermeasure);
            }
        }
        return ocmList;
    }
}
