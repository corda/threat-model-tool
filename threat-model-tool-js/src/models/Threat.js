import BaseThreatModelObject from './BaseThreatModelObject.js';
import CVSSHelper from '../utils/CVSSHelper.js';
import Countermeasure from './Countermeasure.js';
import REFID from './REFID.js';

class Threat extends BaseThreatModelObject {
    constructor(dictData, threatModel, publicAccess = false) {
        super(dictData, threatModel);
        
        this.countermeasures = [];
        this.assets = [];
        this.impactedSecObjs = [];
        this.attackers = [];
        this.threatModel = threatModel;

        if ('description' in dictData) {
            throw new Error(`description is not allowed in Threat ${this.id}, please use 'attack' instead`);
        }

        dictData.CVSS = dictData.CVSS || { base: 'TODO CVSS', vector: '' };
        dictData.fullyMitigated = dictData.fullyMitigated || false;

        for (const [key, value] of Object.entries(dictData)) {
            if (key === 'ticketLink' && publicAccess) {
                continue;
            } else if (key === 'countermeasures') {
                for (const cmData of value) {
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
                for (const secObjData of value) {
                    if ('REFID' in secObjData) {
                        this.impactedSecObjs.push(new REFID(secObjData, this));
                    } else {
                        throw new Error(`REFID needed to reference an impacted Security Objective in: ${this.id}`);
                    }
                }
            } else if (key === 'assets') {
                for (const assetData of value) {
                   this.assets.push(new REFID(assetData, this));
                }
            } else if (key === 'attackers') {
                for (const attackerData of value) {
                    if ('REFID' in attackerData) {
                        this.attackers.push(new REFID(attackerData, this));
                    } else {
                        throw new Error(`REFID needed to reference an actual attacker ID in: ${this.id}`);
                    }
                }
            } else {
                this[key] = value;
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

        this.cvssObject = dictData.CVSS.vector ? new CVSSHelper(dictData.CVSS.vector) : new CVSSHelper("");
    }

    get description() {
        return this.attack ? `**Attack:** ${this.attack}<br/> **Impact:** ${this.impactDesc}` : 'undefined';
    }

    getSmartScoreDesc() {
        return this.cvssObject ? this.cvssObject.getSmartScoreDesc() : 'TODO CVSS';
    }

    getSmartScoreVal() {
        return this.cvssObject ? this.cvssObject.getSmartScoreVal() : 0.0;
    }

    getSmartScoreColor() {
        return this.cvssObject ? this.cvssObject.getSmartScoreColor() : 'gray';
    }

    threatGeneratedTitle() {
        const assetDesc = this.assets.length > 0 ? this.assets.map(asset => `${asset.type || ''} ${asset.title || asset.REFIDValue || ''}`).join(', ') : '';
        return `${this.threatType} in: ${assetDesc}`;
    }
}

export default Threat;
