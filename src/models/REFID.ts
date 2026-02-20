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
        this._id = `REFID_${this.REFIDValue}`;
    }

    resolve(): BaseThreatModelObject | null {
        // Resolve from the root ThreatModel (not nearest TM) so cross-TM references work
        const root = this.getRoot() as any;
        if (!root || !root.getDescendantById) return null;
        return root.getDescendantById(this.REFIDValue);
    }
}
