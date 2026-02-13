import fs from 'fs';
import yaml from 'js-yaml';
import BaseThreatModelObject from './BaseThreatModelObject.js';
import Threat from './Threat.js';
import Asset from './Asset.js';
import SecurityObjective from './SecurityObjective.js';
import Scope from './Scope.js';
import Assumption from './Assumption.js';

class ThreatModel extends BaseThreatModelObject {
    constructor(fileIn, parent = null, publicAccess = false, versionsFilterStr = null) {
        super({}, parent);
        this.fileName = fileIn;
        this.publicAccess = publicAccess;
        this.versionsFilterStr = versionsFilterStr;
        this.threats = [];
        this.assets = [];
        this.securityObjectives = [];
        this.assumptions = [];
        
        if (fileIn) {
            this.loadThreatModel();
        }
    }

    loadThreatModel() {
        const tmDict = this.tryLoadThreatModel(this.fileName);
        if (!tmDict) {
            throw new Error(`YAML file is empty or invalid: ${this.fileName}`);
        }
        this.originDict = tmDict;

        this._id = tmDict.ID;
        this.schemaVersion = tmDict.schemaVersion || 1;

        if (tmDict.scope) {
            this.scope = new Scope(tmDict.scope, this);
        }

        this.loadComponents(tmDict);
    }

    loadComponents(tmDict) {
        if (tmDict.threats) {
            tmDict.threats.forEach(threatDict => {
                const threat = new Threat(threatDict, this, this.publicAccess);
                this.threats.push(threat);
            });
        }

        if (tmDict.assets) {
            tmDict.assets.forEach(assetDict => {
                const asset = new Asset(assetDict, this);
                this.assets.push(asset);
            });
        }

        if (tmDict.securityObjectives) {
            tmDict.securityObjectives.forEach(secObjDict => {
                const secObj = new SecurityObjective(secObjDict, this);
                this.securityObjectives.push(secObj);
            });
        }

        if (tmDict.assumptions) {
            tmDict.assumptions.forEach(assumptionDict => {
                const assumption = new Assumption(assumptionDict, this);
                this.assumptions.push(assumption);
            });
        }
    }

    tryLoadThreatModel(filename) {
        try {
            const fileContents = fs.readFileSync(filename, 'utf8');
            return yaml.load(fileContents);
        } catch (error) {
            throw new Error(`Error loading YAML file ${filename}: ${error.message}`);
        }
    }
}

export default ThreatModel;
