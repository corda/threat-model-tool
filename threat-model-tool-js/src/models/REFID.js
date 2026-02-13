import BaseThreatModelObject from './BaseThreatModelObject.js';

class REFID extends BaseThreatModelObject {
    constructor(dictData, parent) {
        super(dictData, parent);
        this.isReference = true;
        if (!dictData.REFID) {
            throw new Error(`REFID required in dictionary data for ${parent.id}`);
        }
        this.REFIDValue = dictData.REFID;
    }

    resolve() {
        const root = this.getThreatModel();
        if (!root) return null;
        return root.getDescendantById(this.REFIDValue);
    }
}

export default REFID;
