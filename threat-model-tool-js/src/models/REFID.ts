import BaseThreatModelObject from './BaseThreatModelObject.js';

export default class REFID extends BaseThreatModelObject {
    REFIDValue: string;

    constructor(dictData: Record<string, any>, parent: BaseThreatModelObject) {
        super(dictData, parent);
        this.isReference = true;
        if (!dictData.REFID) {
            throw new Error(`REFID required in dictionary data for ${parent.id}`);
        }
        this.REFIDValue = dictData.REFID;
    }

    resolve(): BaseThreatModelObject | null {
        const root = this.getThreatModel();
        if (!root) return null;
        return root.getDescendantById(this.REFIDValue);
    }
}
