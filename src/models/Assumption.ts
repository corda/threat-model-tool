import BaseThreatModelObject from './BaseThreatModelObject.js';

export default class Assumption extends BaseThreatModelObject {
    constructor(dictData: Record<string, any>, parent: BaseThreatModelObject) {
        super(dictData, parent);
    }
}
