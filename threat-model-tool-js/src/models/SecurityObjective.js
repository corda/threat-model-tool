import BaseThreatModelObject from './BaseThreatModelObject.js';
import REFID from './REFID.js';

class SecurityObjective extends BaseThreatModelObject {
    constructor(dictData, parent) {
        super(dictData, parent);
        this.contributesTo = [];

        if (!dictData.group) {
            // throw new Error(`SecurityObjective ${dictData.ID || 'undefined'} needs a 'group' attribute`);
        }

        if (dictData.contributesTo) {
            for (const dict2 of dictData.contributesTo) {
                if (dict2.REFID) {
                    this.contributesTo.push(new REFID(dict2, this));
                }
            }
        }
    }

    linkedImpactMDText() {
        return `<code><a href="#${this.anchor}">${this.id}</a></code>`;
    }

    printAsText() {
        return `\nID: ${this.id} \nDescription: ${this.description}`;
    }
}

export default SecurityObjective;
